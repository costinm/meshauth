package meshauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/costinm/meshauth/pkg/certs"
	"github.com/costinm/meshauth/pkg/tokens"
)

// MeshCfg is used to configure the mesh basic settings related to security.
type MeshCfg struct {
	ConfigLocation string

	// AuthnConfig defines the trust config for the node - the list of signers that are trusted for specific
	// issuers and domains, audiences, etc.
	//
	// Based on Istio jwtRules, but generalized to all signer types.
	//
	// Authz is separated - this only defines who do we trust (and policies on what we trust it for)
	//
	// Destinations and listeners may have their own AuthnConfig - this is the default.
	tokens.AuthnConfig `json:",inline"`

	// Trusted roots, in DER format.
	// Deprecated - AuthnConfig
	RootCertificates [][]byte `json:"roots,omitempty"`

	// Domain is extracted from the cert or set by user, used to verify
	// peer certificates. If not set, will be populated when cert is loaded.
	// Should be a real domain with OIDC keys or platform specific.
	// NOT cluster.local
	Domain string `json:"domain,omitempty"`

	DomainAliases []string `json:"domainAliases,omitempty"`

	// Namespace and Name are extracted from the certificate or set by user.
	// Namespace is used to verify peer certificates
	Namespace string `json:"namespace,omitempty"`

	// Name of the service account. Can be an email or spiffee or just the naked name.
	Name string `json:"name,omitempty"`

	// Deprecated - MDS
	ProjectID string `json:"project_id,omitempty"`
	GSA       string `json:"gsa,omitempty"`

	// Authz: Additional namespaces to allow access from. If no authz rule is set, 'same namespace'
	// and 'istio-system' are allowed.
	AllowedNamespaces []string `json:"allow_namespaces,omitempty"`

	// DER public key
	PublicKey []byte `json:"pub,omitempty"`

	// EC256 key, in base64 format. Used for self-signed identity and webpush.
	// Deprecated
	// EC256Key string `json:"-"`
	// EC256Pub string `json:"-"`

	// MeshAddr is a URL or string representing the primary (bootstrap) address
	// for the mesh config - can be a K8S cluster, XDS server, file.
	MeshAddr string `json:"meshAddr,omitempty"`

	// Dst contains pre-configured or discovered properties for destination services.
	// When running in K8S, "KUBERNETES" is set with the in-cluster config.
	// A .kube/config file can be converted to dst if a subset of auth is used.
	//
	// K8S Services, SSH hosts, etc are also represented as Dst.
	Dst map[string]*Dest `json:"dst,omitempty"`

	TCPUserTimeout time.Duration

	// Timeout used for TLS or SSH handshakes. If not set, 3 seconds is used.
	HandsahakeTimeout time.Duration
}

// Mesh represents a workload identity and associated info required for minimal
// mesh-compatible security. Includes helpers for authentication and
// basic provisioning.
//
// A workload may be associated with multiple service accounts
// and identity providers, and may have multiple certificates.
type Mesh struct {
	*MeshCfg

	// ResourceStore is used to load configs and data on-demand and unmarshal
	// them to the appropriate type.
	//
	// It acts as a filesystem.
	ResourceStore ResourceStore `json:"-"`

	// Primary workload ID TLS certificate and private key. Loaded or generated.
	// Default is to use EC256 certs. The private key can be used to sign JWTs.
	// The public key and sha can be used as a node identity.
	Cert *certs.Certs `json:"-"`

	// AuthProviders - matching kubeconfig user.authProvider.name
	// It is expected to return tokens with the given audience - in case of GCP
	// returns access tokens. If not set the cluster can't be created.
	//
	// A number of pre-defined token sources are used:
	// - gcp - returns GCP access tokens using MDS or default credentials. Used for example by GKE clusters.
	// - k8s - return K8S WorkloadID tokens with the given audience for default K8S cluster.
	// - istio-ca - returns K8S tokens with istio-ca audience - used by Citadel and default Istiod
	// - sts - federated google access tokens associated with GCP identity pools.
	AuthProviders map[string]TokenSource `json:"-"`

	// Default dialer used to connect to host:port extracted from metadata.
	// Defaults to net.Dialer, making real connections.
	//
	// Can be replaced with a mux or egress dialer or router for
	// integrations.
	NetDialer ContextDialer `json:"-"`

	// Mux is used for HTTP and gRPC handler exposed externally.
	//
	// It is the default handler for "hbone" and "hbonec" protocol handlers.
	//
	// The HTTP server on localhost:15000 uses http.DefaultServerMux -
	// which is also used by pprof and others by default and can't be changed.
	// It could also be exposed with 'admin' auth wrapper.
	Mux *http.ServeMux `json:"-"`

	m sync.RWMutex

	HandlerWrapper func(hf http.Handler, op string) http.Handler `json:"-"`
	RTWrapper      func(rt http.RoundTripper) http.RoundTripper  `json:"-"`
}

// The normal pattern of registering in 'init' or startup is simple but
// lacks flexibility. It panics on duplicates, can't remove.
//
// Instead the listener and http servers use a handler that allows swapping
// the Mux, and each module can be re-created with a new Mux.
type HttpProvider interface {

	// TODO: instead create a Mux for domain/prefix

	// The module must use domain and prefix to register with the mux.
	RegisterMux(mux *http.ServeMux)
}

type ResourceStore interface {
	Get(ctx context.Context, s string) (any, error)
}

func New() *Mesh {
	cfg := &MeshCfg{}
	a := &Mesh{
		MeshCfg:       cfg,
		AuthProviders: map[string]TokenSource{},
		NetDialer:     &net.Dialer{},
		Mux:           http.NewServeMux(),
	}

	// TODO: mesh only option. By default we trust public platform certs
	// a.trustedCertPool = x509.NewCertPool(),

	// Bootstrap mesh identity from settings/files

	if cfg.HandsahakeTimeout == 0 {
		cfg.HandsahakeTimeout = 5 * time.Second
	}

	return a
}

func (mesh *Mesh) Provision(ctx context.Context) error {

	return nil
}

func (mesh *Mesh) Discover(ctx context.Context, addr string) (*Dest, error) {
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

	if ok {
		return c, nil
	}

	dstany, err := mesh.ResourceStore.Get(ctx, "/service/"+addr)
	if err != nil {
		return nil, err
	}

	if dstany == nil {
		// Defaults, std config, no need to hold it.
		c = &Dest{Addr: addr}
	} else {
		// cached by store or client - no need to hold it
		if dd, ok := dstany.(*Dest); ok {
			c = dd
		} else {
			return nil, fmt.Errorf("invalid type for destination: %T", dstany)
		}
	}
	// TODO: use discovery to find info about service addr, populate from XDS on-demand or DNS
	// TODO: on-demand, DNS lookups, etc
	//mesh.addDest(c)
	//c.LastUsed = time.Now()
	return c, nil
}

var (
	TokenPayload = tokens.TokenPayload
	DecodeJWT    = tokens.DecodeJWT
	JwtRawParse  = tokens.JwtRawParse
)

// GetToken is the default token source for the object.
// Will try:
// - MDS
// - AuthProvider["K8S"],"GCP"
// - locally signed token, using the mesh private key.
//
// TODO: add some audience policy - for example googleapis.com or
// .mesh.internal.
func (mesh *Mesh) GetToken(ctx context.Context, aud string) (string, error) {

	// If mds is configured ( for example on GCP/GKE) - use it
	// It can return access and ID tokens.
	// Off GCP - it should not be enabled.
	//mdsmod, _ := mesh.ResourceStore.Get(ctx, "mds")
	//if mdsmod != nil {
	//	tok, err := mdsmod.(TokenSource).GetToken(ctx, aud)
	//	if err == nil {
	//		return tok, err
	//	}
	//}

	if aud == "" {
		// Not an ID token - google or k8s federated token
		// gcp_fed can only return access tokens.
		for _, s := range []string{"gcp", "gcp_fed"} {
			ts := mesh.AuthProviders[s]
			if ts != nil {
				tok, err := ts.GetToken(ctx, aud)
				if err == nil {
					return tok, err
				}
			}
		}
	}

	// gcp source should only be registered if we have a GSA set, otherwise
	// it can't get ID tokens (and returns federated access tokens)
	for _, s := range []string{"gcp", "k8s"} {
		ts := mesh.AuthProviders[s]
		if ts != nil {
			tok, err := ts.GetToken(ctx, aud)
			if err == nil {
				return tok, err
			}
		}
	}
	return mesh.getTokenLocal(ctx, aud)
}

func (mesh *Mesh) getTokenLocal(ctx context.Context, aud string) (string, error) {
	jwt := &tokens.JWT{
		Aud: []string{aud},
	}
	return jwt.Sign(mesh.Cert.PrivateKey), nil
}

func (mesh *Mesh) L4HttpTransport(ctx context.Context) *http.Transport {
	return &http.Transport{
		DialContext: mesh.DialContext,
		// If not set, DialContext and TLSClientConfig are used
		DialTLSContext:        mesh.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		Proxy:                 http.ProxyFromEnvironment,
	}
}

// DialContext should connect to the address, using one of the modules
// and config - falling back to the default dialer.
//
// Normal golang - network is "tcp" and address is host:port - or custom values are allowed.
//
// All forwarding/tunneling methods should call this method to establish
// outbound connections.
func (mesh *Mesh) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {

	c, err := mesh.Discover(ctx, addr)
	if c == nil {
		host, _, _ := net.SplitHostPort(addr)
		c, err = mesh.Discover(ctx, host)
	}

	if c != nil {

		if c.Dialer != nil {
			return c.Dialer.DialContext(ctx, network, addr)
		} else {
			return nil, errors.New("Missing dialer " + c.Addr + " for " + addr)
		}

		// TODO: routing, etc - based on endpoints and TcpRoutes
	}

	// TODO: if egress gateway is set, use it ( redirect all unknown to egress )
	// TODO: CIDR range of Endpoints, Nodes, VIPs to use hbone
	// TODO: if port, use SNI or match clusters
	nc, err := mesh.NetDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	// If net connection is cut, by default the socket may linger for up to 20 min without detecting this.
	// Extracted from gRPC - needs to apply at TCP socket level
	//if c.TCPUserTimeout != 0 {
	//	syscall.SetTCPUserTimeout(nc, c.TCPUserTimeout)
	//}

	return nc, err
}

// ------------ Old code to be removed -------------
// 5 usages left - move to appinit

// FromEnv will attempt to identify and Init the certificates.
// This should be called from main() and for normal app use.
//
// New can be used in tests or for fine control over
// what cert is loaded.
//
// - default GKE/Istio location for workload identity
// - /var/run/secrets/...FindC
// - /etc/istio/certs
// - $HOME/.ssh/id_ecdsa - if it is in standard pem format
//
// ssh-keygen -t ecdsa -b 256 -m PEM -f id_ecdsa
//
// If a cert is found, the identity is extracted from the cert. The
// platform is expected to refresh the cert.
//
// If a cert is not found, Cert field will be nil, and the app should
// use one of the methods of getting a cert or call InitSelfSigned.
func FromEnv(ctx context.Context, base string) (*Mesh, error) {
	ma := New()
	err := ma.fromEnv(ctx, base)

	return ma, err
}

// FromEnv will initialize Mesh using local files and env variables.
func (mesh *Mesh) fromEnv(ctx context.Context, base string) error {

	// Detect cloudrun
	ks := os.Getenv("K_SERVICE")
	if ks != "" {
		sn := ks
		verNsName := strings.SplitN(ks, "--", 2)
		if len(verNsName) > 1 {
			sn = verNsName[1]
		}
		mesh.Name = sn
		mesh.AuthnConfig.Issuers = append(mesh.AuthnConfig.Issuers,
			&tokens.TrustConfig{
				Issuer: "https://accounts.google.com",
			})
	}

	// Determine the workload name, using environment variables or hostname.
	// This should be unique, typically pod-xxx-yyy

	if mesh.Name == "" {
		name := os.Getenv("POD_NAME")
		if name == "" {
			name = os.Getenv("WORKLOAD_NAME")
		}
		mesh.Name = name
	}

	if mesh.Name == "" {
		name, _ := os.Hostname()
		if strings.Contains(name, ".") {
			parts := strings.SplitN(name, ".", 2)
			mesh.Name = parts[0]
			if mesh.Domain == "" {
				mesh.Domain = parts[1]
			}
		} else {
			mesh.Name = name
		}
	}

	if mesh.Domain == "" {
		mesh.Domain = "mesh.internal"
	}

	return nil
}
