package meshauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/costinm/meshauth/util"
)

var (
	Debug = false

	// Client used for local node ( MDS, etc) - not encrypted
	LocalHttpClient *http.Client
)

var (
	// Must be set in main().
	defaultAuth *MeshAuth
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
	AuthnConfig `json:",inline"`

	// Will attempt to Init/reload certificates from this directory.
	// If empty, FromEnv will auto-detect.
	// For mounted secret of type kubernetes.io/tls, the keys are tls.key, tls.crt
	// Deprecated - Credential
	CertDir string `json:"certDir,omitempty"`

	// Trusted roots, in DER format.
	// Deprecated - AuthnConfig
	RootCertificates [][]byte `json:"roots,omitempty"`

	// Domain is extracted from the cert or set by user, used to verify
	// peer certificates. If not set, will be populated when cert is loaded.
	// Should be a real domain with OIDC keys or platform specific.
	// NOT cluster.local
	Domain    string `json:"domain,omitempty"`

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
	// Deprecated - Authz
	AllowedNamespaces []string

	// If no authz rule is set, 'same namespace' and 'istio-system' are allowed.
	Authz []*AuthzRule

	// Private key. UGate primary key is EC256, in PEM format.
	// Used for client and server auth for all protocols.
	// If not set, will be loaded from CertDir tls.key file, or auto-generated.
	Priv string `json:"priv,omitempty"`

	// PEM certificate chain
	CertBytes string `json:"cert,omitempty"`

	// DER public key
	PublicKey []byte `json:"pub,omitempty"`


	// EC256 key, in base64 format. Used for self-signed identity and webpush.
	EC256Key string
	EC256Pub string

	ec256Priv []byte `json:-`

	MDS *util.Metadata `json:"mds,omitempty"`

	// TokenProvider is a URL used to get access tokens, as a GCP-like MDS server,
	// for client.
	//
	// Default is http://169.254.169.245
	// For local dev and debugging it can be replaced.
	// It can also be a full http:// or https:// URL.
	// Deprecated - Credentials
	TokenProvider    string `json:"token_source,omitempty"`

	// Dst contains pre-configured or discovered properties for destination services.
	// When running in K8S, "KUBERNETES" is set with the in-cluster config.
	// A .kube/config file can be converted to dst if a subset of auth is used.
	//
	// K8S Services, SSH hosts, etc are also represented as Dst.
	Dst map[string]*Dest `json:"dst,omitempty"`

	// Additional port listeners.
	// Routes: listen on 127.0.0.1:port
	// Ingress: listen on 0.0.0.0:port (or actual IP)
	//
	// Port proxies: will register a listener for each port, forwarding to the
	// given address.
	//
	// K8S Gateway: key is the section name (converting from list to map)
	Listeners map[string]*PortListener `json:"listeners,omitempty"`
}

func NewMeshAuthCfg() MeshCfg {
	return MeshCfg{
		Dst: map[string]*Dest{},
		Listeners: map[string]*PortListener{},

	}
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

type AuthzRule struct {

	// Authz: Additional namespaces to allow access from.
	AllowedNamespaces []string
}

// AuthnConfig specifies trusted sources for incoming authentication.
//
// Common case is as a global config, but may be specified per listener.
//
// Unlike Istio, this also covers SSH and Cert public keys - treating all signed mechanisms the same.
//
type AuthnConfig struct {
	// Trusted issuers for auth.
	//
	Issuers []*TrustConfig `json:"trust,omitempty"`

	// If set, accept truncated tokens.
	// TODO: restrict to the main h2 listener, auto-set based on env.
	CloudrunIAM bool `json:"cloudruniam,omitempty"`

	// Top level audiences. The rule may have a custom audience as well, if it matches this is
	// ignored.
	// If empty, the hostname is used as a default.
	Audiences []string `json:"aud,omitempty"`
}

// Configure the settings for one trusted identity provider. This is primarily used for server side authenticating
// clients, but may also be used for clients authenticating servers - it defines what is trusted to provided identities.
//
// Extended from Istio JWTRule - but unified with certificate providers.
type TrustConfig struct {

	// Example: https://foobar.auth0.com
	// Example: 1234567-compute@developer.gserviceaccount.com (for tokens signed by a GSA)
	// In GKE, format is https://container.googleapis.com/v1/projects/$PROJECT/locations/$LOCATION/clusters/$CLUSTER
	// and the discovery doc is relative (i.e. standard).
	// The keys typically are $ISS/jwks - but OIDC document should be loaded.
	//
	// Must match the Issuer in the JWT token.
	// As 'converged' auth, this is also used to represent SSH or TLS CAs.
	Issuer string `json:"issuer,omitempty"`

	// Delegation indicates a mechanism of delegation - can be:
	// - TODO: a URL indicating a different issuer that is replacing the signature.
	// - NO_SIGNATURE - indicates that the workload is running in a Cloudrun-like env, where
	// the JWT is verified by a frontend and replaced with a token without signature.
	// - header:NAME - the jwt is decoded and placed in a header.
	// - xfcc -
	//Delegation string

	// Identification for the frontend that has validated the identity
	//
	//Delegator string

	// The list of JWT
	// [audiences](https://tools.ietf.org/html/rfc7519#section-4.1.3).
	// that are allowed to access. A JWT containing any of these
	// audiences will be accepted.
	//
	// The service name will be accepted if audiences is empty.
	//
	// Example:
	//
	// ```yaml
	// audiences:
	// - bookstore_android.apps.example.com
	//   bookstore_web.apps.example.com
	// ```
	// Istio had this next to issuer - in meshauth it is one level higher, all
	// issuers can use the same aud ( it is based on hostname of the node or service )
	//Audiences []string `protobuf:"bytes,2,rep,name=audiences,proto3" json:"audiences,omitempty"`

	// URL of the provider's public key set to validate signature of the
	// JWT. See [OpenID Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).
	//
	// Optional if the key set document can either (a) be retrieved from
	// [OpenID
	// Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) of
	// the issuer or (b) inferred from the email domain of the issuer (e.g. a
	// Google service account).
	//
	// Example: `https://www.googleapis.com/oauth2/v1/certs`
	//
	//
	// Note: Only one of jwks_uri and jwks should be used. jwks_uri will be ignored if it does.
	JwksUri string `json:"jwks_uri,omitempty"`

	// JSON Web Key Set of public keys to validate signature of the JWT.
	// See https://auth0.com/docs/jwks.
	//
	// Note: In Istio, only one of jwks_uri and jwks should be used. jwks_uri
	// will be ignored if Jwks is present - but it doesn't seem right.
	//
	// TODO: mutating webhook to populate this field, controller JOB to rotate
	Jwks string `protobuf:"bytes,10,opt,name=jwks,proto3" json:"jwks,omitempty"`

	// List of header locations from which JWT is expected. For example, below is the location spec
	// if JWT is expected to be found in `x-jwt-assertion` header, and have "Bearer " prefix:
	// ```
	//   fromHeaders:
	//   - name: x-jwt-assertion
	//     prefix: "Bearer "
	// ```
	//FromHeaders []*JWTHeader `protobuf:"bytes,6,rep,name=from_headers,json=fromHeaders,proto3" json:"from_headers,omitempty"`
	// List of query parameters from which JWT is expected. For example, if JWT is provided via query
	// parameter `my_token` (e.g /path?my_token=<JWT>), the config is:
	// ```
	//   fromParams:
	//   - "my_token"
	// ```
	//FromParams []string `protobuf:"bytes,7,rep,name=from_params,json=fromParams,proto3" json:"from_params,omitempty"`

	// This field specifies the header name to output a successfully verified JWT payload to the
	// backend. The forwarded data is `base64_encoded(jwt_payload_in_JSON)`. If it is not specified,
	// the payload will not be emitted.
	// OutputPayloadToHeader string `protobuf:"bytes,8,opt,name=output_payload_to_header,json=outputPayloadToHeader,proto3" json:"output_payload_to_header,omitempty"`

	// If set to true, the orginal token will be kept for the ustream request. Default is false.
	//ForwardOriginalToken bool `protobuf:"varint,9,opt,name=forward_original_token,json=forwardOriginalToken,proto3" json:"forward_original_token,omitempty"`

	// PEM provides the set of public keys or certificates in-line.
	//
	// Not recommended - use pem_location instead so it can be reloaded, unless the trust config is reloaded itself.
	//
	// Extension to Istio JwtRule - specify the public key as PEM. This may include multiple
	// public keys or certificates. This will be populated by a mutating webhook and updated
	// by a job.
	PEM string `json:"pem,omitempty"`

	// Location of a PEM file providing the public keys or certificates of the trusted source.
	// Directory or URL. If provided, will be reloaded periodically or based on expiration time.
	PEMLocation string `json:"pem_location,omitempty"`

	// Extension to Isio JwtRule - cached subset of the OIDC discovery document
	OIDC *OIDCDiscDoc `json:"oidc,omitempty"`

	// Not stored - the actual keys or verifiers for this issuer.
	Key interface{} `json:-"`

	// KeysById is populated from the Jwks config or PEM
	KeysByKid map[string]interface{} `json:-`

	m         sync.Mutex `json:-`
	lastFetch time.Time  `json:-`
	exp       time.Time  `json:-`
}

// PortListener represents the configuration for a real port listener.
// uGate has a set of special listeners that multiplex requests:
// - socks5 dest
// - iptables original dst ( may be combined with DNS interception )
// - NAT dst address
// - SNI for TLS
// - :host header for HTTP
// - ALPN - after TLS handshake
//
// Multiplexed channels do an additional lookup to find the listener
// based on the channel address.
type PortListener struct {
	Name string `json:"name,omitempty"`

	// Port number - by default listens on the public address.
	Port int32 `json:"port,omitempty"`

	// Address address (ex :8080). This is the requested address.
	//
	// BTS, SOCKS, HTTP_PROXY and IPTABLES have default ports and bindings, don't
	// need to be configured here.
	Address string `json:"address,omitempty"`

	// Port can have multiple protocols:
	// If missing or other value, this is a dedicated port, specific to a single
	// destination.
	// Gateway API defines HTTP, HTTPS, TCP, TLS, UDP
	// HBone Extensions are SNI, SOCKS5, HBONE, HBONEC, H2C
	Protocol string `json:"protocol,omitempty"`

	// Extensions

	// ForwardTo where to forward the proxied connections.
	// Used for accepting on a dedicated port. Will be set as MeshCluster in
	// the stream, can be mesh node.
	// host:port format.
	ForwardTo string `json:"forwardTo,omitempty"`

	// Internal state.
	NetListener net.Listener `json:-`
}

func (l *PortListener) Accept() (net.Conn, error) {
	return l.NetListener.Accept()
}

func (l *PortListener) Close() error {
	return l.NetListener.Close()
}
func (l *PortListener) Addr() net.Addr {
	return l.NetListener.Addr()
}

func (l *PortListener) GetPort() int32 {
	if l.Port != 0 {
		return l.Port
	}
	_, p, _ := net.SplitHostPort(l.Address)
	pp, _ := strconv.Atoi(p)
	l.Port = int32(pp)
	return l.Port
}

// MeshAuth represents a workload identity and associated info required for minimal
// mesh-compatible security. Includes helpers for authentication and basic provisioning.
//
// By default it will attempt to Init a workload cert, and extract info from the cert.
//
// A workload may be associated with multiple service accounts and identity providers, and
// may have multiple certificates.
type MeshAuth struct {
	*MeshCfg

	// Primary workload ID TLS certificate and private key. Loaded or generated.
	// Default is to use EC256 certs. The private key can be used to sign JWTs.
	// The public key and sha can be used as a node identity.
	Cert *tls.Certificate

	// cached PublicKeyBase64 encoding of the public key, for EC256 VAPID.
	PublicKeyBase64 string

	// Public key as base32 SHA (52 bytes)
	PubID           string

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

	// Primary VIP, Created from the PublicKey key, will be included in the self-signed cert.
	VIP6 net.IP

	// Same as VIP6, but as uint64
	VIP64 uint64

	// Explicit certificates (lego), key is hostname from file
	//
	CertMap map[string]*tls.Certificate

	// GetCertificateHook allows plugging in an alternative certificate provider.
	GetCertificateHook func(host string) (*tls.Certificate, error)

	// Auth token providers
	AuthProviders map[string]TokenSource

	// Metadata about this node. Also, the default TokenSource.
	MDS                *MDS

	ClientSessionCache tls.ClientSessionCache

	Stop chan struct{}

	// Location is the location of the node - derived from MDS or config.
	Location string
}

// Interface for very simple storage abstraction.
//
// Can have a simple in-memory, fs implementation, as well as K8S, XDS or
// database backends.
type Store interface {
	// Get an object blob by name
	Get(name string) ([]byte, error)

	// Save a blob by name.
	Set(conf string, data []byte) error

	// List the configs starting with a prefix, of a given type.
	List(name string, tp string) ([]string, error)
}

// TokenSource is a common interface for anything returning Bearer or other kind of tokens.
type TokenSource interface {
	// GetToken for a given audience.
	GetToken(context.Context, string) (string, error)
}

type TokenSourceFunc func(context.Context, string) (string, error)

func (f TokenSourceFunc) GetToken(ctx context.Context, aud string) (string, error) {
	return f(ctx, aud)
}

// PerRPCCredentials defines the common interface for the credentials which need to
// attach security information to every RPC (e.g., oauth2).
// This is the interface used by gRPC - should be implemented by all TokenSource to
// allow use with gRPC.
type PerRPCCredentials interface {
	// GetRequestMetadata gets the current request metadata, refreshing
	// tokens if required. This should be called by the transport layer on
	// each request, and the data should be populated in headers or other
	// context. If a status code is returned, it will be used as the status
	// for the RPC. uri is the URI of the entry point for the request.
	// When supported by the underlying implementation, ctx can be used for
	// timeout and cancellation. Additionally, RequestInfo data will be
	// available via ctx to this call.
	// TODO(zhaoq): Define the set of the qualified keys instead of leaving
	// it as an arbitrary string.
	GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error)
	// RequireTransportSecurity indicates whether the credentials requires
	// transport security.
	RequireTransportSecurity() bool
}

// NewMeshAuth initializes the auth systems based on config.
//
// Must call SetTLSCertificate to initialize or one of the methods that finds or generates the primary identity.
func NewMeshAuth(cfg *MeshCfg) *MeshAuth {
	if cfg == nil {
		cfg = &MeshCfg{}
	}
	if cfg.Dst == nil {
		cfg.Dst = map[string]*Dest{}
	}
	a := &MeshAuth{
		MeshCfg:       cfg,
		CertMap:       map[string]*tls.Certificate{},
		meshCertPool:  x509.NewCertPool(),
		MDS:           &MDS{},
		AuthProviders: map[string]TokenSource{},
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

	a.MDS.MeshAuth = a

	if cfg.EC256Key != "" {
		a.setEC256Vapid()
	}

	if cfg.Priv != "" && cfg.CertBytes != "" {
		a.SetCertPEM(cfg.Priv, cfg.CertBytes)
	}

	if a.CertDir != "" {
		c, cb, err := loadCertFromDir(a.CertDir)
		if err == nil {
			a.SetTLSCertificate(c)
		}
		a.CertBytes = string(cb)
	}

		return a
}

// FromEnv will attempt to identify and Init the certificates.
// This should be called from main() and for normal app use.
//
// NewMeshAuth can be used in tests or for fine control over
// what cert is loaded.
//
// - default GKE/Istio location for workload identity
// - /var/run/secrets/...FindC
// - /etc/istio/certs
// - $HOME/
//
// If a cert is found, the identity is extracted from the cert. The
// platform is expected to refresh the cert.
//
// If a cert is not found, Cert field will be nil, and the app should
// use one of the methods of getting a cert or call InitSelfSigned.
func FromEnv(cfg *MeshCfg) (*MeshAuth, error) {
	a := NewMeshAuth(cfg)

	// If running in K8S - and the pod config doesn't prevent access to K8S -
	// detect and configure a KUBERNETES cluster and set self info from K8S env.
	a.inCluster()

	cfg = a.MeshCfg
	// Attempt to locate existing workload certs from the cert dir.
	// TODO: attempt to get certs from an agent.
	if cfg.CertDir == "" {
		// Try to find the certificate directory
		if _, err := os.Stat(filepath.Join("./", "key.pem")); !os.IsNotExist(err) {
			a.CertDir = "./"
		} else if _, err := os.Stat(filepath.Join("./", "tls.key")); !os.IsNotExist(err) {
				a.CertDir = "./"
		} else if _, err := os.Stat(filepath.Join(workloadCertDir, privateKey)); !os.IsNotExist(err) {
			a.CertDir = workloadCertDir
		} else if _, err := os.Stat(filepath.Join(legacyCertDir, "key.pem")); !os.IsNotExist(err) {
			a.CertDir = legacyCertDir
		} else if _, err := os.Stat(filepath.Join("/var/run/secrets/istio", "key.pem")); !os.IsNotExist(err) {
			a.CertDir = "/var/run/secrets/istio/"
		}
	}

	if a.Cert == nil && a.CertDir != "" && a.CertDir != "-" {
		return a, a.initFromDirPeriodicStart()
	}

	return a, nil
}

func (ma *MeshAuth) inCluster() *Dest {
	const (
		tokenFile  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
		rootCAFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	)
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if len(host) == 0 || len(port) == 0 {
		return nil
	}

	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil
	}

	ca, err := os.ReadFile(rootCAFile)

	fts := &FileTokenSource{TokenFile: tokenFile}
	c := &Dest{
		Addr:          "https://" + net.JoinHostPort(host, port),
		TokenProvider: fts,
	}
	c.AddCACertPEM(ca)

	namespace, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err == nil {
		ma.Namespace = string(namespace)
	}

	jwt := DecodeJWT(string(token))
	if ma.Namespace == "" {
		ma.Namespace = jwt.K8S.Namespace
	}
	if ma.Name == "" {
		ma.Name = jwt.Name
	}

	ma.Dst["KUBERNETES"] = c

	return c
}

// ------------ Helpers around TokenSource

type PerRPCCredentialsFromTokenSource struct {
	TokenSource
}

func (s *PerRPCCredentialsFromTokenSource) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	t, err := s.GetToken(ctx, uri[0])
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"authorization": "Bearer " + t,
	}, nil
}

func (s *PerRPCCredentialsFromTokenSource) RequireTransportSecurity() bool { return false }

// TODO: file based access, using /var/run/secrets/ file pattern and mounts.
// TODO: Exec access, using /usr/lib/google-cloud-sdk/bin/gke-gcloud-auth-plugin (11M) for example
//  name: gke_costin-asm1_us-central1-c_td1
//  user:
//    exec:
//      apiVersion: client.authentication.k8s.io/v1beta1
//      command: gke-gcloud-auth-plugin
//      installHint: Install gke-gcloud-auth-plugin for use with kubectl by following
//        https://cloud.google.com/blog/products/containers-kubernetes/kubectl-auth-changes-in-gke
//      provideClusterInfo: true

// /usr/lib/google-cloud-sdk/bin/gke-gcloud-auth-plugin
// {
//    "kind": "ExecCredential",
//    "apiVersion": "client.authentication.k8s.io/v1beta1",
//    "spec": {
//        "interactive": false
//    },
//    "status": {
//        "expirationTimestamp": "2022-07-01T15:55:01Z",
//        "token": ".." // ya29
//    }
//}

// File or static token source
type FileTokenSource struct {
	TokenFile string
}

func (s *FileTokenSource) GetToken(context.Context, string) (string, error) {
	if s.TokenFile != "" {
		tfb, err := os.ReadFile(s.TokenFile)
		if err != nil {
			return "", err
		}
		return string(tfb), nil
	}
	return "", nil
}

type StaticTokenSource struct {
	Token string
}

func (s *StaticTokenSource) GetToken(context.Context, string) (string, error) {
	return s.Token, nil
}

type AudienceOverrideTokenSource struct {
	TokenSource TokenSource
	Audience    string
}

func (s *AudienceOverrideTokenSource) GetToken(ctx context.Context, _ string) (string, error) {
	return s.TokenSource.GetToken(ctx, s.Audience)
}

const Default = "default"

// InitK8SInCluster will check if running in cluster, and init based on the K8S
// environment files.
func InitK8SInCluster(ma *MeshAuth) (*Dest, error) {
	const (
		tokenFile  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
		rootCAFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	)
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if len(host) == 0 || len(port) == 0 {
		return nil, nil
	}

	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, err
	}

	ca, err := os.ReadFile(rootCAFile)

	c := &Dest{
		Addr:          "https://" + net.JoinHostPort(host, port),
		TokenProvider: &FileTokenSource{TokenFile: tokenFile},
	}
	c.AddCACertPEM(ca)

	namespace, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err == nil {
		ma.Namespace = string(namespace)
	}

	jwt := DecodeJWT(string(token))
	if ma.Namespace == "" {
		ma.Namespace = jwt.K8S.Namespace
	}
	if ma.Name == "" {
		ma.Name = jwt.Name
	}

	ma.Dst["K8S"] = c

	ma.AuthProviders["K8S"] = &K8STokenSource{
		Dest:           c,
		Namespace:      ma.Namespace,
		ServiceAccount: ma.Name}

	return c, nil
}
