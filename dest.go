package meshauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

/*
New model (2024):

- Dest is a HOST:port or URL - for a specific (frontend) service. The hostname portion
  will be resolved with DNS, EDS, meshauth to get 'endpoints'.

- Hosts is a pod, VM, container with a FQDN hostname, addresses and labels. Doesn't include
  ports - it is expected if the host is returned for a 'dest', it will listen on the right port.

- hosts may be directly visible or exposed 'via' a different jump host - SSH, SNI, waypoints.

- when connecting to a frontend (Dest), by default it is expected it will have a DNS cert, unless
  the resolved endpoint's host has specific config (spiffe cert, etc).

Meshauth is primarily concerned with authenticating the server and client, but it also
includes secure discovery and bootstrap. It is NOT concerned with protocols.

Difference between 'Service frontend' and 'workload endpoint' is subtle and not always visible.
We have a FQDN:port or VIP:port. The FQDN may resolve (DNS or EDS) to multiple IPs - which
can be Init balancers/waypoints or real endpoints. A host may have multiple IPs too.

From client perspective the main difference is that for Service we may get weights and localities
and perform advanced client-side Init balancing and routing.

 */


// Dest represents a destination and associated security info.
//
// In Istio this is represented as DestinationRule, Envoy - Cluster, K8S Service (the backend side).
//
// This is primarily concerned with the security aspects (auth, transport),
// and include 'trusted' attributes from K8S configs or JWT/cert.
//
// K8S clusters can be represented as a Dest - rest.Config Host is Addr, CACertPEM
//
// Unlike K8S and Envoy, the port is not required.
//
// This is part of the config - either static or on-demand. The key is the virtual
// address or IP:port that is either captured or set as backendRef in routes.
type Dest struct {

	// Addr is the address of the destination.
	//
	// For HTTP, Addr is the URL, including any required path prefix, for the destination.
	//
	// For TCP, Addr is the TCP address - VIP:port or DNS:port format. tcp:// is assumed.
	//
	// For K8S service it should be in the form serviceName.namespace.svc:svcPort
	// The cluster suffix is assumed to be 'cluster.local' or the custom k8s suffix,
	// equivalent to cluster.server in kubeconfig.
	//
	// This can also be an 'original dst' address for individual endpoints.
	//
	// Individual IPs (real or relay like waypoints or egress GW, etc) will be in
	// the info.addrs field.
	Addr string `json:"addr,omitempty"`

	// Proto determines how to talk with the Dest.
	// Could be 'hbone' (compat with Istio), 'h2c', 'h2', 'ssh', etc.
	// If not set - Dial will use regular TCP or TLS, depending on the other settings.
	Proto string `json:"protocol,omitempty"`

	//FQDN []string `json:"fqdn,omitempty"`

	// VIP is the set of IPs assigned to this destination.
	// Only set for (frontend) Services. Used when capturing traffic for this service
	//
	//VIP []string `json:"alpn,omitempty"`


	// Sources of trust for validating the peer destination.
	// Typically, a certificate - if not set, SYSTEM certificates will be used for non-mesh destinations
	// and the MESH certificates for destinations using one of the mesh domains.
	// If not set, the nodes' trust config is used.
	TrustConfig *TrustConfig `json:"trust,omitempty"`

	// Expected SANs - if not set, the DNS host in the address is used.
	// For mesh FQDNs, the namespace will be checked ( second part of the FQDN )
	DNSSANs []string `json:"dns_san,omitempty"`
	//IPSANs  []string `json:"ip_san,omitempty"`
	URLSANs []string `json:"url_san,omitempty"`

	// SNI to use when making the request. Defaults to hostname in Addr
	SNI string `json:"sni,omitempty"`

	ALPN []string `json:"alpn,omitempty"`

	// Location is set if the cluster has a default location (not global).
	Location string `json:"location,omitempty"`

	// If empty, the cluster is using system certs or SPIFFE CAs - as configured in
	// MeshAuth.
	//
	// Otherwise, it's the configured root certs list, in PEM format.
	// May include multiple concatenated roots.
	//
	// TODO: allow root SHA only.
	CACertPEM []byte `json:"ca_cert,omitempty"`

	// From CDS

	// timeout for new network connections to endpoints in cluster
	ConnectTimeout           time.Duration `json:"connect_timeout,omitempty"`
	TCPKeepAlive             time.Duration `json:"tcp_keep_alive,omitempty"`
	TCPUserTimeout           time.Duration `json:"tcp_user_timeout,omitempty"`
	//MaxRequestsPerConnection int

	// Default values for initial window size, initial window, max frame size
	InitialConnWindowSize int32 `json:"initial_conn_window,omitempty"`
	InitialWindowSize     int32 `json:"initial_window,omitempty"`
	MaxFrameSize          uint32 `json:"max_frame_size,omitempty"`

	Labels map[string]string `json:"labels,omitempty"`

	// If set, this is required to verify the certs of dest if https is used
	// If not set, system certs are used
	roots *x509.CertPool `json:-`

	// Credentials to use to authenticate to this destination.

	// If set, Bearer tokens will be added.
	TokenProvider TokenSource `json:-`

	// If set, a token source with this name is used. The provider must be set in MeshEnv.AuthProviders
	// If not found, no tokens will be added. If found, errors getting tokens will result
	// in errors connecting.
	// In K8S - it will be the well-known token file.
	TokenSource string `json:"tokens,omitempty"`

	// WebpushPublicKey is the client's public key. From the getKey("p256dh") or keys.p256dh field.
	// This is used for Dest that accepts messages encrypted using webpush spec, and may
	// be used for validating self-signed destinations - this is expected to be the public
	// key of the destination.
	// Primary public key of the node.
	// EC256: 65 bytes, uncompressed format
	// RSA: DER
	// ED25519: 32B
	// Used for sending encryted webpush message
	// If not known, will be populated after the connection.
	WebpushPublicKey []byte `json:"pub,omitempty"`

	// Webpush Auth is a secret shared with the peer, used in sending webpush
	// messages.
	WebpushAuth []byte `json:"auth,omitempty"`
	// TLS-related settings

	// Cached client
	httpClient            *http.Client `json:-`

	// If set, the destination is using HTTP protocol - and this is the roundtripper to use.
	// HttpClient() returns a http client initialized for this destination.
	// For special cases ( reverse connections in h2r ) it will be a *http2.ClientConn.
	//
	RoundTripper            http.RoundTripper `json:-`
	InsecureSkipTLSVerify bool `json:"insecure,omitempty"`

	Dialer ContextDialer `json:-`

	// L4Secure is set if the destination can be reached over a secure L4 network (ambient, VPC, IPSec, secure CNI, etc)
	L4Secure bool `json:"l4secure,omitempty"`

	// Last packet or registration from the peer.
	LastSeen time.Time `json:"-"`


	Backoff time.Duration `json:"-"`
	Dynamic bool `json:"-"`
}

// ContextGetter allows getting a Context associated with a stream or
// request or other high-level object. Based on http.Request
type ContextGetter interface {
	Context() context.Context
}



// ContextDialer is same with x.net.proxy.ContextDialer
// Used to create the actual connection to an address using the mesh.
// The result may have metadata, and be an instance of util.Stream.
//
// A uGate implements this interface, it is the primary interface
// for creating streams where the caller does not want to pass custom
// metadata. Based on net and addr and handshake, if destination is
// capable we will upgrade to BTS and pass metadata. This may also
// be sent via an egress gateway.
//
// For compatibility, 'net' can be "tcp" and addr a mangled hostname:port
// Mesh addresses can be identified by the hostname or IP6 address.
// External addresses will create direct connections if possible, or
// use egress server.
//
// TODO: also support 'url' scheme
type ContextDialer interface {
	// Dial with a context based on tls package - 'once successfully
	// connected, any expiration of the context will not affect the
	// connection'.
	DialContext(ctx context.Context, net, addr string) (net.Conn, error)
}

// HttpClient returns a http client configured to talk with this Dest using a secure connection.
// - if CACertPEM is set, will be used instead of system
//
// The client is cached in Dest.
func (d *Dest) HttpClient() *http.Client {
	if d.httpClient != nil {
		return d.httpClient
	}

	if d.L4Secure {
		d.httpClient = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
			},
		}
	} else {
		tlsConfig := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: d.InsecureSkipTLSVerify,
		}

		if len(d.CACertPEM) != 0 {
			tlsConfig.RootCAs = x509.NewCertPool()
			if !tlsConfig.RootCAs.AppendCertsFromPEM(d.CACertPEM) {
				return nil //, errors.New("certificate authority doesn't contain any certificates")
			}
		}

		d.httpClient = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}
	}

	return d.httpClient
}

func (d *Dest) RoundTrip(r *http.Request) (*http.Response, error) {
	return d.HttpClient().Do(r)
}

// WIP
func (d *Dest) DialTLS(a *MeshAuth, nc net.Conn) (*tls.Conn, error) {
	tlsClientConfig := a.TLSClientConf(d, d.SNI, d.Addr)
	tlsTun := tls.Client(nc, tlsClientConfig)
	ctx, cf := context.WithTimeout(context.Background(), 3 * time.Second)
	defer cf()

	err := tlsTun.HandshakeContext(ctx)

	if err != nil {
		return nil, err
	}
	return tlsTun, nil
}


func (d *Dest) GetCACertPEM() []byte {
	return d.CACertPEM
}

// AddToken will add a token to the request, using the 'token source' of the
// destination.
func (c *Dest) AddToken(ma *MeshAuth, req *http.Request, aut string) error {
	if c.TokenSource != "" {
		tp := ma.AuthProviders[c.TokenSource]
		if tp != nil {
			t, err := tp.GetToken(req.Context(), aut)
			if err != nil {
				return err
			}
			req.Header.Add("authorization", "Bearer "+t)
		}
	}
	if c.TokenProvider != nil {
		t, err := c.TokenProvider.GetToken(req.Context(), aut)
		if err != nil {
			return err
		}
		req.Header.Add("authorization", "Bearer "+t)
		//for k, v := range t {
		//	req.Header.Add(k, v)
		//}
	}

	// TODO: use default workload identity token source for MeshAuth

	return nil
}

func (d *Dest) CertPool() *x509.CertPool {
	if d.roots == nil {
		d.roots = x509.NewCertPool()
		if d.CACertPEM != nil {
			ok := d.roots.AppendCertsFromPEM(d.CACertPEM)
			if !ok {
				log.Println("Failed to parse CACertPEM", "addr", d.Addr)
			}
		}
	}
	return d.roots
}

func (d *Dest) AddCACertPEM(pems []byte) error {
	if d.roots == nil {
		d.roots = x509.NewCertPool()
	}
	if d.CACertPEM != nil {
		d.CACertPEM = append(d.CACertPEM, '\n')
		d.CACertPEM = append(d.CACertPEM, pems...)
	} else {
		d.CACertPEM = pems
	}
	if !d.roots.AppendCertsFromPEM(pems) {
		return errors.New("Failed to decode PEM")
	}
	return nil
}

// Helpers for making REST and K8S requests for a k8s-like API.

// RESTRequest is a REST or K8S style request. Will be used with a Dest.
//
// It is based on/inspired from kelseyhightower/konfig - which uses the 'raw'
// K8S protocol to avoid a big dependency. Google, K8S and many other APIs have
// a raw representation and don't require complex client libraries and depdencies.
// No code generation or protos are used - raw JSON in []byte is used, caller
// can handle marshalling.
//
// Close to K8S raw REST client - but without the builder style.
type RESTRequest struct {
	Method    string
	Namespace string
	Kind      string
	Name      string

	Body []byte

	// If set, will be added at the end (must include ?). For example ?watch=0
	Query string
}

func (kr *RESTRequest) HttpRequest(ctx context.Context, d *Dest) *http.Request {
	var path string
	if kr.Namespace != "" {
		path = fmt.Sprintf("/api/v1/namespaces/%s/%ss", kr.Namespace, kr.Kind)
	} else {
		path = "/apis/" + kr.Kind
	}
	if kr.Name != "" { // else - list request
		path = path + "/" + kr.Name
	}
	if kr.Query != "" {
		path = path + kr.Query
	}

	var req *http.Request
	m := kr.Method
	if kr.Method == "" {
		if kr.Body == nil {
			m = "GET"
		} else {
			m = "POST"
		}
	}
	if kr.Body == nil {
		req, _ = http.NewRequestWithContext(ctx, m, d.Addr+path, nil)
	} else {
		req, _ = http.NewRequestWithContext(ctx, m, d.Addr+path, bytes.NewReader(kr.Body))
	}

	req.Header.Add("content-type", "application/json")

	if d.TokenProvider != nil {
		t, err := d.TokenProvider.GetToken(ctx, d.Addr)
		if err == nil {
			req.Header.Add("authorization", "Bearer "+t)
		}
	}
	return req

}

// Load will populate the Secret object from a K8S-like service.
// This also works with real K8S.
//
// 'kind' can be 'configmap', 'secret', etc for using K8S-style URL format
func (d *Dest) Load(ctx context.Context, obj interface{}, kind, ns string, name string) error {
	rr := &RESTRequest{
		Namespace: ns,
		Kind:      kind,
		Name:      name,
	}

	res, err := d.HttpClient().Do(rr.HttpRequest(ctx, d))
	if err != nil {
		return err
	}

	data, err := io.ReadAll(res.Body)
	err = json.Unmarshal(data, obj)
	if err != nil {
		return err
	}

	return nil
}


func (n *Dest) BackoffReset() {
	n.Backoff = 0
}

func (n *Dest) BackoffSleep() {
	if n.Backoff == 0 {
		n.Backoff = 5 * time.Second
	}
	time.Sleep(n.Backoff)
	if n.Backoff < 5*time.Minute {
		n.Backoff = n.Backoff * 2
	}
}
