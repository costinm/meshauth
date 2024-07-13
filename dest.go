package meshauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/costinm/meshauth/pkg/apis/authn"
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

	// Addr is the main (VIP or URL) address of the destination.
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
	// MeshCluster WorkloadID - the cluster name in kube config, hub, gke - cluster name in XDS
	// Defaults to Base addr - but it is possible to have multiple clusters for
	// same address ( ex. different users / token providers).
	//
	// Examples:
	// GKE cluster: gke_PROJECT_LOCATION_NAME
	//
	// For mesh nodes:
	// ID is the (best) primary id known for the node. Format is:
	//    base32(SHA256(EC_256_pub)) - 32 bytes binary, 52 bytes encoded
	//    base32(ED_pub) - same size, for nodes with ED keys.
	//
	// For non-mesh nodes, it is a (real) domain name or IP if unknown.
	// It may include port, or even be a URL - the external destinations may
	// have different public keys on different ports.
	//
	// The node may be a virtual IP ( ex. K8S/Istio service ) or name
	// of a virtual service.
	//
	// If IPs are used, they must be either truncated SHA or included
	// in the node cert or the control plane must return metadata and
	// secure low-level network is used (like wireguard)
	//
	// Required for secure communication.
	//
	// Examples:
	//  -  [B32_SHA]
	//  -  [B32_SHA].reviews.bookinfo.svc.example.com
	//  -  IP6 (based on SHA or 'trusted' IP)
	//  -  IP4 ('trusted' IP)
	//
	// IPFS:
	// http://<gateway host>/ipfs/CID/path
	// http://<cid>.ipfs.<gateway host>/<path>
	// http://gateway/ipns/IPNDS_ID/path
	// ipfs://<CID>/<path>, ipns://<peer WorkloadID>/<path>, and dweb://<IPFS address>
	//
	// Multiaddr: TLV
	ID string `json:"id,omitempty"`


	// Sources of trust for validating the peer destination.
	// Typically, a certificate - if not set, SYSTEM certificates will be used for non-mesh destinations
	// and the MESH certificates for destinations using one of the mesh domains.
	// If not set, the nodes' trust config is used.
	TrustConfig *authn.TrustConfig `json:"trust,omitempty"`

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
	// Mesh.
	//
	// Otherwise, it's the configured root certs list, in PEM format.
	// May include multiple concatenated roots.
	//
	// TODO: allow root SHA only.
	// TODO: move to trust config
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

	// Hosts are workload addresses associated with the backend service.
	//
	// If empty, the MeshCluster Addr will be used directly - it is expected to be
	// a FQDN or VIP that is routable - either a service backed by an LB or handled by
	// ambient or K8S.
	//
	// This may be pre-configured or result of discovery (IPs, extra properties).
	Hosts []*Host `json:"hosts,omitempty"`
}


// Host represents the properties of a single workload.
// By default, clusters resolve the endpoints dynamically, using DNS or EDS or other
// discovery mechanisms.
type Host struct {
	// Labels for the workload. Extracted from pod info - possibly TXT records
	//
	// 'hbone' can be used for a custom hbone endpoint (default 15008).
	//
	Labels map[string]string `json:"labels,omitempty"`

	//LBWeight int `json:"lb_weight,omitempty"`
	//Priority int

	// Address is an IP where the host can be reached.
	// It can be a real IP (in the mesh, direct) or a jump host.
	//
	Address string `json:"addr,omitempty"`

	// FQDN of the host. Used to check host cert.
	Hostname string
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
func (d *Dest) DialTLS(a *Mesh, nc net.Conn) (*tls.Conn, error) {
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

// TODO: add a DialTLSContext using DNS-SEC for Cert SHA, as well as a direct CERT-SHA

func (d *Dest) GetCACertPEM() []byte {
	return d.CACertPEM
}

// AddToken will add a token to the request, using the 'token source' of the
// destination.
func (d *Dest) AddToken(ma *Mesh, req *http.Request, aut string) error {
	if d.TokenSource != "" {
		tp := ma.AuthProviders[d.TokenSource]
		if tp != nil {
			t, err := tp.GetToken(req.Context(), aut)
			if err != nil {
				return err
			}
			req.Header.Add("authorization", "Bearer "+t)
		}
	}
	if d.TokenProvider != nil {
		t, err := d.TokenProvider.GetToken(req.Context(), aut)
		if err != nil {
			return err
		}
		req.Header.Add("authorization", "Bearer "+t)
		//for k, v := range t {
		//	req.Header.Add(k, v)
		//}
	}

	// TODO: use default workload identity token source for Mesh

	return nil
}

func (d *Dest) TokenGetter(m *Mesh) TokenSource {
	return TokenSourceFunc(func(ctx context.Context, aut string) (string, error) {
		if d.TokenSource != "" {
			tp := m.AuthProviders[d.TokenSource]
			if tp != nil {
				t, err := tp.GetToken(ctx, aut)
				if err != nil {
					return "", err
				}
				return t, nil
			}
		}
		if d.TokenProvider != nil {
			t, err := d.TokenProvider.GetToken(ctx, aut)
			if err != nil {
				return "", err
			}
			return t, nil
		}

		// TODO: use default workload identity token source for Mesh
		return "", nil
	})
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


func (d *Dest) BackoffReset() {
	d.Backoff = 0
}

func (d *Dest) BackoffSleep() {
	if d.Backoff == 0 {
		d.Backoff = 5 * time.Second
	}
	time.Sleep(d.Backoff)
	if d.Backoff < 5*time.Minute {
		d.Backoff = d.Backoff * 2
	}
}


// GetDest returns a cluster for the given address, or nil if not found.
func (mesh *Mesh) GetDest(addr string) *Dest {
	mesh.m.RLock()
	c := mesh.Dst[addr]
	// Make sure it is set correctly.
	if c != nil && c.ID == "" {
		c.ID = addr
	}

	mesh.m.RUnlock()
	return c
}


// Cluster will get an existing cluster or create a dynamic one.
// Dynamic clusters can be GC and loaded on-demand.
func (mesh *Mesh) GetOrAddDest(ctx context.Context, addr string) (*Dest, error) {
	// TODO: extract cluster from addr, allow URL with params to indicate how to connect.
	//host := ""
	//if strings.Contains(dest, "//") {
	//	u, _ := url.Parse(dest)
	//
	//	host, _, _ = net.SplitHostPort(u.Host)
	//} else {
	//	host, _, _ = net.SplitHostPort(dest)
	//}
	//if strings.HasSuffix(host, ".svc") {
	//	hc.H2Gate = hg + ":15008" // hbone/mtls
	//	hc.ExternalMTLSConfig = auth.GenerateTLSConfigServer()
	//}
	//// Initialization done - starting the proxy either on a listener or stdin.

	// 1. Find the cluster for the address. If not found, create one with the defaults or use on-demand
	// if XDS server is configured
	mesh.m.RLock()
	c, ok := mesh.Dst[addr]
	mesh.m.RUnlock()

	// TODO: use discovery to find info about service addr, populate from XDS on-demand or DNS
	if !ok {
		// TODO: on-demand, DNS lookups, etc
		c = &Dest{Addr: addr, Dynamic: true, ID: addr}
		mesh.addDest(c)
	}
	//c.LastUsed = time.Now()
	return c, nil
}

// addDest will add a cluster to be used for Dial and RoundTrip.
// The 'Addr' field can be a host:port or IP:port.
// If id is set, it can be host:port or hostname - will be added as a destination.
// The service can be IP:port or URLs
func (mesh *Mesh) addDest(c *Dest) *Dest {
	mesh.m.Lock()
	mesh.Dst[c.Addr] = c

	if c.ID != "" {
		mesh.Dst[c.ID] = c
	}

	//c.UGate = hb
	//if c.ConnectTimeout == 0 {
	//	c.ConnectTimeout = hb.Auth.ConnectTimeout.Duration
	//}
	mesh.m.Unlock()

	return c
}
