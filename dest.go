package meshauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"time"
)

/*
2025:

- don't really need listeners - H2C and forwarding/handlers are good enough  abstractions, let ztunnel handle crypto and waypoint inbound rules, or
  std libraries at h2c layer.

- if dest is handled by istio or on secure net (wireguard, etc) - no crypto needed, no control plane. Use CIDR.

- on-demand security info for workloads not handled by ztunnel/istio. DNS, well known, probes.

- Dest is based on DestinationRule

- model is L7 resources with K8S style of URLs.

- L4 over H2 or SSH


*/
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

type Discoverer interface {

	// Discover will use configs, DNS, XDS, K8S or other means to find the properties of a destination.
	// If none is found, the default is:
	// - if addr is a general FQDN, use it as a standard internet destination.
	// - if addr is a public IP - use the standard Dialer.
	// - if addr has '.internal' or '.local' - use mesh root certificates and HBONE or SSH protocol.
	// - for private IP ranges - same
	//
	// Custom Discover can set egress gateways or adjust.
	Discover(ctx context.Context, addr string) (*Dest, error)
}

type ContextDialer interface {
	// Dial with a context based on tls package - 'once successfully
	// connected, any expiration of the context will not affect the
	// connection'.
	DialContext(ctx context.Context, net, addr string) (net.Conn, error)
}

// TokenSource is a common interface for anything returning Bearer or other kind of tokens.
type TokenSource interface {
	// GetToken for a given audience.
	GetToken(context.Context, string) (string, error)
}

// Dest represents the metadata associated with an address.
//
// It is discovered from multiple sources - local config, control plane, DNS.
//
// This is primarily concerned with the security aspects (auth, transport),
// and include 'trusted' attributes from K8S configs or JWT/cert.
//
// K8S clusters can be represented as a Dest - rest.Config Host is Addr,
// CACertPEM, same for all REST or gRPC services. For L7 destinations a HttpClient
// and RoundTripper are created based on the metadata. This is required because
// the Transport is associated with the trust configs.
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
	// Name is the (best) primary id known for the node. Format is:
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

	// Name is the 'basename' or alias of the service.
	//
	Name string `json:"id,omitempty"`

	// Domains are the DNS domains of the service.
	// A service can be published in multiple DNS domains.
	//Domain []string `json:"domains"`

	// Identity required by this dest - if not set, inferred from JWT/cert
	//Principal string

	// Static token to use. May be a long lived K8S service account secret or other long-lived creds.
	// Alternative: static token source
	//Token string

	// If empty, the cluster is using system certs or SPIFFE CAs - as configured in
	// Mesh.
	//
	// Otherwise, it's the configured root certs list, in PEM format.
	// May include multiple concatenated roots.
	//
	// TODO: allow root SHA only.
	// TODO: move to trust config
	CACertPEM string `json:"ca_cert,omitempty"`

	// Sources of trust for validating the peer destination.
	// Typically, a certificate - if not set, SYSTEM certificates will be used for non-mesh destinations
	// and the MESH certificates for destinations using one of the mesh domains.
	// If not set, the nodes' trust config is used.
	// TrustConfig *tokens.TrustConfig `json:"trust,omitempty"`
	// If set, Bearer tokens will be added.
	TokenProvider TokenSource `json:-`

	// If set, a token source with this name is used. The provider must be set in MeshEnv.AuthProviders
	// If not found, no tokens will be added. If found, errors getting tokens will result
	// in errors connecting.
	// In K8S - it will be the well-known token file.
	TokenSource string `json:"tokens,omitempty"`

	// Location is set if the cluster has a default location (not global).
	//Location string `json:"location,omitempty"`

	// timeout for new network connections to endpoints in cluster
	//ConnectTimeout time.Duration `json:"connect_timeout,omitempty"`
	//TCPKeepAlive   time.Duration `json:"tcp_keep_alive,omitempty"`
	//TCPUserTimeout time.Duration `json:"tcp_user_timeout,omitempty"`
	//MaxRequestsPerConnection int

	// Default values for initial window size, initial window, max frame size
	//InitialConnWindowSize int32  `json:"initial_conn_window,omitempty"`
	//InitialWindowSize     int32  `json:"initial_window,omitempty"`
	//MaxFrameSize          uint32 `json:"max_frame_size,omitempty"`

	// Labels map[string]string `json:"labels,omitempty"`

	// If set, this is required to verify the certs of dest if https is used
	// If not set, system certs are used
	// roots *x509.CertPool `json:-`

	// Cached client
	httpClient *http.Client `json:-`

	// If set, the destination is using HTTP protocol - and this is the roundtripper to use.
	// HttpClient() returns a http client initialized for this destination.
	// For special cases ( reverse connections in h2r ) it will be a *http2.ClientConn.
	//
	RoundTripper          http.RoundTripper `json:-`
	InsecureSkipTLSVerify bool              `json:"insecure,omitempty"`

	Dialer ContextDialer `json:-`

	// L4Secure is set if the destination can be reached over a secure L4 network (ambient, VPC, IPSec, secure CNI, etc)
	L4Secure bool `json:"l4secure,omitempty"`

	// Last packet or registration from the peer.
	//LastSeen time.Time `json:"-"`

	Backoff time.Duration `json:"-"`

	// Pods are workload addresses associated with the backend service.
	// While the interface is not K8S specific, using the term since 'host'
	// or 'node' or 'vm' are too generic and even more confusing.
	//
	// If empty, the MeshCluster Addr will be used directly - it is expected to be
	// a FQDN or VIP that is routable - either a service backed by an LB or handled by
	// ambient or K8S.
	//
	// This may be pre-configured or result of discovery (IPs, extra properties).
	//Hosts []*Pod `json:"pods,omitempty"`
}

/*
  "Service" or "Virtual Host" or "load balancing" is a very different layer from
  individual hostnames and pods.

  Both use a FQDN, both have some cert verification and other similar options.
  However, a Service is resolved to a set of 'Pods' and focused on proper weights
  and load balancing.

  So it seems better to have clear separation:
  - a Pod is a container or VM running on a Host
  - a Host is a physical machine (or VM) that runs Pods (containers or nested VMs),
    and it has network connections, possibly public IPs.
  - a Service is a FQDN that resolves to an virtual IP which is transparently mapped
    to Pods, at L2 or L7 as a real gateway. Client has no control.
  - a client LoadBalaner is a service like EDS that maps a FQDN to a stream of
    weighted endpoints under client control.

  The first 3 involve a FQDN resolved to (few) IPs - client uses an IP on same
  network or can try all. Client doesn't know what the destination is.

*/

// Pod represents the properties of a single workload.
// By default, clusters resolve the endpoints dynamically, using DNS or EDS or other
// discovery mechanisms.
//type Pod struct {
//	// Labels for the workload. Extracted from pod info - possibly TXT records
//	//
//	// 'hbone' can be used for a custom hbone endpoint (default 15008).
//	//
//	Labels map[string]string `json:"labels,omitempty"`
//
//	//LBWeight int `json:"lb_weight,omitempty"`
//	//Priority int
//
//	// Address is an IP where the host can be reached.
//	// It can be a real IP (in the mesh, direct) or a jump host.
//	//
//	Address string `json:"addr,omitempty"`
//	Via string `json:"via,omitempty"`
//
//	// FQDN of the host. Used to check host cert.
//	Hostname string
//}

func (d *Dest) String() string {
	return d.Addr
}

// HttpClient returns a http client configured to talk with this Dest using a secure connection.
// - if CACertPEM is set, will be used instead of system
//
// The client is cached in Dest.
func (d *Dest) HttpClient() *http.Client {
	if d.httpClient != nil {
		return d.httpClient
	}

	t := &http.Transport{}
	d.httpClient = &http.Client{
		Timeout:   5 * time.Second,
		Transport: t,
	}

	if d.L4Secure {
		//h.DialTLSContext = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		//	var d net.Dialer
		//	return d.DialContext(ctx, network, addr)
		//}

		// Replaces:
		//&http.Client{
		//	Transport: &http2.Transport{
		//		AllowHTTP: true,
		//		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		//			var d net.Dialer
		//			return d.DialContext(ctx, network, addr)
		//		},
		//	},
		//
		//h.ReadIdleTimeout = 10000 * time.Second
		//h.StrictMaxConcurrentStreams = false

		t.Protocols = new(http.Protocols)
		t.Protocols.SetUnencryptedHTTP2(true)
		t.Protocols.SetHTTP1(true)
	} else if d.InsecureSkipTLSVerify {
		t.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		}
	} else if len(d.CACertPEM) != 0 {
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM([]byte(d.CACertPEM))
		t.TLSClientConfig.RootCAs = certPool
	}

	return d.httpClient
}

//func (d *Dest) DialContext(ctx context.Context, net, addr string) (net.Conn, error) {
//	// H2 dial or regular dial using a tunnel
//	return nil, nil
//}

func (d *Dest) RoundTrip(r *http.Request) (*http.Response, error) {
	return d.HttpClient().Do(r)
}

// TODO: add a DialTLSContext using DNS-SEC for Cert SHA, as well as a direct CERT-SHA

// Helpers for making REST and K8S requests for a k8s-like API.

// BackoffReset and Sleep implement the backoff interface
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

func (d *Dest) AddTrustPEM(c []byte) {
	//if d.Trust == nil {
	//	d.Trust = certs.Trust{}
	//}
	d.CACertPEM = string(c)

}
