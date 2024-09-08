package meshauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/costinm/meshauth/pkg/apis/authn"
)

var (
	Debug = false
)

// MeshCfg is used to configure the mesh basic settings related to security.
//
// It includes definition of listeners and cluters (dst) - with associated keys/certs.
// This package does not provide any protocol or listening.
type MeshCfg struct {

	// AuthnConfig defines the trust config for the node - the list of signers that are trusted for specific
	// issuers and domains, audiences, etc.
	//
	// Based on Istio jwtRules, but generalized to all signer types.
	//
	// Authz is separated - this only defines who do we trust (and policies on what we trust it for)
	//
	// Destinations and listeners may have their own AuthnConfig - this is the default.
	authn.AuthnConfig `json:",inline"`

	// Will attempt to Init/reload certificates and configs from this directory.
	//
	// If empty, default platform locations will be used. "-" will disable loading configs.
	// TODO: URLs, k8s, etc.
	ConfigLocation string `json:"configLocation,omitempty"`

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
	EC256Key string `json:"-"`
	EC256Pub string `json:"-"`

	// MeshAddr is a URL or string representing the primary (bootstrap) address
	// for the mesh config - can be a K8S cluster, XDS server, file.
	MeshAddr string `json:"meshAddr,omitempty"`

	// Dst contains pre-configured or discovered properties for destination services.
	// When running in K8S, "KUBERNETES" is set with the in-cluster config.
	// A .kube/config file can be converted to dst if a subset of auth is used.
	//
	// K8S Services, SSH hosts, etc are also represented as Dst.
	Dst map[string]*Dest `json:"dst,omitempty"`


	// Modules contains the enabled modules for this mesh.
	// The value is a list of key/pair settings.
	// The name of the module will be used to locate the component.
	Modules []*Module `json:"modules,omitempty"`

	// Additional defaults for outgoing connections.
	// Probably belong to Dest.
	ConnectTimeout Duration `json:"connect_timeout,omitempty"`

	TCPUserTimeout time.Duration

	// Timeout used for TLS or SSH handshakes. If not set, 3 seconds is used.
	HandsahakeTimeout time.Duration

	Env map[string]string
}

// Deprecated
func (m *Mesh) Module(name string) *Module {
	for _, mm := range m.Modules {
		if mm.Name == name {
			return mm
		}
	}
	return nil
}


func ModuleT[T interface{}](m *Mesh, name string) *T {
	for _, mm := range m.Modules {
		if mm.Name == name {
			//*res = mm.Module.(T)
			tt :=  mm.Module.(*T)
			return tt
		}
	}
	return nil
}


// Credential identifies a source of client private info to use for authentication
// with a destination.
//
// It can be a shared secret (token), private key, etc.
type Credential struct {
	// Identity asserted by this credential - if not set inferred from JWT/cert
	Principal string

	// SetCert the cert credential from this directory (or URL)
	// The 'default' credential will use well-known locations.
	// All other certs are either explicit or relative to CertDir/NAME
	CertLocation string

	// If set, the token source will be used.
	// Using gRPC interface which returns the full auth string, not only the token
	//
	TokenProvider PerRPCCredentials `json:-`

	// Static token to use. May be a long lived K8S service account secret or other long-lived creds.
	// Alternative: static token source
	Token string

	// TokenSource is the name of the token provier.
	// If set, a token source with this name is used. The provider must be set in MeshEnv.AuthProviders
	TokenSource string

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
	//
	// TODO: use CertLocation instead - can extract the key from a cert, may also include the cert along.
	//WebpushPublicKey []byte `json:"pub,omitempty"`

	// Webpush Auth is a secret shared with the peer, used in sending webpush messages.
	// TODO: use Token instead (it is a static secret)
	//WebpushAuth []byte `json:"auth,omitempty"`
}

// Mesh represents a workload identity and associated info required for minimal
// mesh-compatible security. Includes helpers for authentication and basic provisioning.
//
// By default it will attempt to Init a workload cert, and extract info from the cert.
//
// A workload may be associated with multiple service accounts and identity providers, and
// may have multiple certificates.
type Mesh struct {
	*MeshCfg

	// Trusted roots - used for verification. RawSubject is used as key - Subjects() return the DER list.
	// This is 'write only', used as a cache in verification.
	//
	// TODO: copy Istiod multiple trust domains code. This will be a map[trustDomain]roots and a
	// list of TrustDomains. XDS will return the info via ProxyConfig.
	// This can also be done by krun - loading a config map with same info.
	trustedCertPool *x509.CertPool

	meshCertPool    *x509.CertPool

	// Node ID - pod ID, CloudRun instanceID, hostname.
	//
	// Must be DNS compatible, case insensitive, max 63
	ID string `json:"id,omitempty"`

	// Primary VIP, Created from the PublicKey key
	VIP6 net.IP

	// Same as VIP6, but as uint64
	VIP64 uint64

	// Primary workload ID TLS certificate and private key. Loaded or generated.
	// Default is to use EC256 certs. The private key can be used to sign JWTs.
	// The public key and sha can be used as a node identity.
	Cert *tls.Certificate `json:-`

	// Private key. UGate primary key is EC256, in PEM format.
	// Used for client and server auth for all protocols.
	// Deprecated - method to get it from Cert.
	Priv string `json:"priv,omitempty"`

	// PEM certificate chain
	CertBytes string `json:"cert,omitempty"`

	// Explicit certificates (lego), key is hostname from file
	//
	CertMap map[string]*tls.Certificate

	// GetCertificateHook allows plugging in an alternative certificate provider.
	GetCertificateHook func(host string) (*tls.Certificate, error)

	// AuthProviders - matching kubeconfig user.authProvider.name
	// It is expected to return tokens with the given audience - in case of GCP
	// returns access tokens. If not set the cluster can't be created.
	//
	// A number of pre-defined token sources are used:
	// - gcp - returns GCP access tokens using MDS or default credentials. Used for example by GKE clusters.
	// - k8s - return K8S WorkloadID tokens with the given audience for default K8S cluster.
	// - istio-ca - returns K8S tokens with istio-ca audience - used by Citadel and default Istiod
	// - sts - federated google access tokens associated with GCP identity pools.
	AuthProviders map[string]TokenSource

	ClientSessionCache tls.ClientSessionCache

	Stop chan struct{}

	// Location is the location of the node - derived from MDS or config.
	Location       string

	// MuxDialers are used to create an association with a peer and multiplex connections.
	// HBone, SSH, etc can act as mux dialers.
	MuxDialers map[string]ContextDialer

	// Default dialer used to connect to host:port extracted from metadata.
	// Defaults to net.Dialer, making real connections.
	//
	// Can be replaced with a mux or egress dialer or router for
	// integration.
	NetDialer ContextDialer

	// Mux is used for HTTP and gRPC handler exposed externally.
	//
	// It is the default handler for "hbone" and "hbonec" protocol handlers.
	//
	// The HTTP server on localhost:15000 uses http.DefaultServerMux -
	// which is also used by pprof and others by default and can't be changed.
	// It could also be exposed with 'admin' auth wrapper.
	Mux *http.ServeMux

	DebugMux *http.ServeMux

	Routers map[string]Router
	Handlers map[string]http.Handler

	// Active modules, by name
	Listeners map[string]*Module

	m sync.RWMutex

	HandlerWrapper func(hf http.Handler, op string) http.Handler
	RTWrapper      func(rt http.RoundTripper) http.RoundTripper
}

func (mesh *Mesh) GetCert() *tls.Certificate {
	return mesh.Cert
}

// New initializes the auth systems based on config.
//
// Must call setTLSCertificate to initialize or one of the methods that finds or generates the primary identity.
func New(cfg *MeshCfg) *Mesh {
	if cfg == nil {
		cfg = &MeshCfg{}
	}
	if cfg.Dst == nil {
		cfg.Dst = map[string]*Dest{}
	}
	a := &Mesh{
		MeshCfg:       cfg,
		Listeners: map[string]*Module{},
		CertMap:       map[string]*tls.Certificate{},
		meshCertPool:  x509.NewCertPool(),
		AuthProviders: map[string]TokenSource{},
		MuxDialers:   map[string]ContextDialer{},
		NetDialer: &net.Dialer{},
		Mux:           http.NewServeMux(),

		// By default use a small cache for tickets. Will be keyed by SNI or address.
		// When connecting end to end to a service SNI, the workloads should NOT send
		// tickets - since each will have a different key.
		// Only if a sync key is used should they be allowed - but that should be
		// controlled server side, since we can't control the clients to not attempt.
		ClientSessionCache: tls.NewLRUClientSessionCache(64),
	}

	// TODO: mesh only option. By default we trust public platform certs
	// a.trustedCertPool = x509.NewCertPool(),

	sp, _ := x509.SystemCertPool()
	a.trustedCertPool = sp.Clone()

	// Bootstrap mesh identity from settings/files

	if cfg.HandsahakeTimeout == 0 {
		cfg.HandsahakeTimeout = 5 * time.Second
	}

	if a.ConfigLocation != "" {
		c, cb, err := loadCertFromDir(a.ConfigLocation)
		if err == nil {
			a.setTLSCertificate(c)
		}
		a.CertBytes = string(cb)
	}

	return a
}

// GetRaw will look in all config sources associated with the mesh
// and attempt to locate the config.
func (mesh *Mesh) GetRaw(base string, suffix string) []byte {
	env := mesh.Env[base]
	if env != "" {
		return []byte(env)
	}

	basecfg := os.Getenv(base)
	if basecfg != "" {
		return []byte(basecfg)
	}

	if mesh.ConfigLocation == "-" {
		return nil
	}
	if mesh.ConfigLocation != "" {
		fb, err := os.ReadFile(mesh.ConfigLocation + "/" + base + suffix)
		if err == nil {
			return fb
		}
	}

	fb, err := os.ReadFile("./" + base + suffix)
	if err == nil {
		return fb
	}

	fb, err = os.ReadFile("/" + base + "/" + base + suffix)
	if err == nil {
		return fb
	}

	return nil
}


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
	mdsmod := mesh.Module("mds")
	if mdsmod != nil {
		tok, err := mdsmod.Module.(TokenSource).GetToken(ctx, aud)
		if err == nil {
			return tok, err
		}
	}

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
	return mesh.GetTokenLocal(ctx, aud)
}


func  (mesh *Mesh) GetTokenLocal(ctx context.Context,  aud string) (string, error) {
	jwt := &JWT{
		Aud: []string{aud},
	}
	return jwt.Sign(mesh.Cert.PrivateKey), nil
}

func  (mesh *Mesh) HttpTransport(ctx context.Context)  *http.Transport {
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


