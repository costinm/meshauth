package meshauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// This handles the ideal mesh case - platform managed workload certificates.
// Also handles pilot-agent managing the certs.

// TLS notes:
// - using HandshakeContext with custom verification for workload identity (spiffe)
//   - instead of x509.VerifyOptions{DNSName} - based on ServerName from the config, which
//     can be overriden by client.
//
// - native library also supports nested TLS - if the RoundTripStart method is overriden and scheme is https,
//    it will do a TLS handshake anyway and RoundTripStart can implement TLS for the outer tunnel.

// MeshAuth represents a workload identity and associated info required for minimal
// mesh-compatible security. Includes helpers for authentication and basic provisioning.
//
// By default will attempt to load a workload cert, and extract info from the cert.
type MeshAuth struct {
	// Primary certificate and private key. Loaded or generated.
	Cert *tls.Certificate

	// Will attempt to load/reload certificates from this directory.
	CertDir string

	// MeshTLSConfig is a tls.Config that requires mTLS with a spiffee identity,
	// using the configured roots, trustdomains.
	//
	// By default only same namespace or istio-system are allowed - can be changed by
	// setting AllowedNamespaces. A "*" will allow all.
	MeshTLSConfig *tls.Config

	// TrustDomain is extracted from the cert or set by user, used to verify
	// peer certificates. If not set, will be populated when cert is loaded.
	// Should be 'cluster.local', a real domain with OIDC keys or platform specific.
	TrustDomain string

	// Namespace and Name are extracted from the certificate or set by user.
	// Namespace is used to verify peer certificates
	Namespace string
	Name      string

	// Additional namespaces to allow access from. By default 'same namespace' and 'istio-system' are allowed.
	AllowedNamespaces []string

	// Trusted roots - used for verification. RawSubject is used as key - Subjects() return the DER list.
	// This is 'write only', used as a cache in verification.
	//
	// TODO: copy Istiod multiple trust domains code. This will be a map[trustDomain]roots and a
	// list of TrustDomains. XDS will return the info via ProxyConfig.
	// This can also be done by krun - loading a config map with same info.
	trustedCertPool *x509.CertPool

	// Root CAs, in DER format. CertPool only stores, can't retrieve.
	RootCertificates [][]byte

	// Private key to use in both server and client authentication.
	// ED22519: 32B
	// EC256: DER
	// RSA: DER
	Priv      []byte
	PublicKey []byte `json:"pub,omitempty"`
	// cached PublicKeyBase64 encoding of the public key, for EC256 VAPID.
	// Set by SetVapid,
	PublicKeyBase64 string
	PubID           string

	// Node ID - derived from the public key if not set explicitly as base32 encoding
	// of the pub64. May also be the pod ID, hostname. The DNS system or discovery should
	// be able to use it as a key and return IPs.
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
}

// NewMeshAuth creates the auth object, without any certifcates.
// Must call SetTLSCertificate to initialize or one of the methods that finds or generates the cert.
func NewMeshAuth() *MeshAuth {
	a := &MeshAuth{
		trustedCertPool: x509.NewCertPool(),
	}
	return a
}

// FromEnv will attempt to identify and load the certificates.
// - default GKE/Istio location for workload identity
// - /var/run/secrets/...FindC
// - /etc/istio/certs
// - $HOME/
func FromEnv(dir string, save bool) (*MeshAuth, error) {
	a := NewMeshAuth()

	if dir != "" {
		a.CertDir = dir
		return a, a.initFromDir()
	}
	if _, err := os.Stat(filepath.Join("./", "key.pem")); !os.IsNotExist(err) {
		a.CertDir = "./"
	} else if _, err := os.Stat(filepath.Join(WorkloadCertDir, privateKey)); !os.IsNotExist(err) {
		a.CertDir = WorkloadCertDir
	} else if _, err := os.Stat(filepath.Join(legacyCertDir, "key.pem")); !os.IsNotExist(err) {
		a.CertDir = legacyCertDir
	} else if _, err := os.Stat(filepath.Join("/var/run/secrets/istio", "key.pem")); !os.IsNotExist(err) {
		a.CertDir = "/var/run/secrets/istio/"
	}
	if a.CertDir != "" {
		return a, a.initFromDir()
	}

	a.CertMap = a.GetCerts()

	if a.Cert != nil {
		return a, nil
	}

	// Init with self-signed certs
	a.initSelfSigned("")

	if save {
		a.SaveCerts(".")
	}

	return a, nil
}

func NewAuth(name, domain string) *MeshAuth {
	if name == "" {
		if os.Getenv("POD_NAME") != "" {
			name = os.Getenv("POD_NAME") + "." + os.Getenv("POD_NAMESPACE")
		} else {
			name, _ = os.Hostname()
		}
	}
	if domain == "" {
		domain = os.Getenv("DOMAIN")
	}
	if domain == "" {
		domain = "c1.webinf.info"
	}

	auth := &MeshAuth{
		Name: name,
	}
	auth.TrustDomain = domain
	auth.trustedCertPool = x509.NewCertPool()

	auth.initSelfSigned("")

	c0 := auth.Cert
	pk := c0.PrivateKey

	var pubkey crypto.PublicKey
	if priv, ok := pk.(*ecdsa.PrivateKey); ok {
		auth.Priv = priv.D.Bytes()
		auth.PublicKey = elliptic.Marshal(elliptic.P256(), priv.X, priv.Y) // starts with 0x04 == uncompressed curve
		pubkey = priv.Public()
	} else if priv, ok := pk.(*ed25519.PrivateKey); ok {
		auth.Priv = *priv
		edpub := PublicKey(priv)
		auth.PublicKey = edpub.(ed25519.PublicKey)
		pubkey = edpub
	} else if priv, ok := pk.(*rsa.PrivateKey); ok {
		edpub := PublicKey(priv)
		auth.Priv = MarshalPrivateKey(priv)
		auth.PublicKey = MarshalPublicKey(priv.Public())
		pubkey = edpub
	}

	auth.VIP6 = Pub2VIP(auth.PublicKey)
	auth.VIP64 = auth.NodeIDUInt(auth.PublicKey)
	// Based on the primary EC256 key
	auth.PublicKeyBase64 = base64.RawURLEncoding.EncodeToString(auth.PublicKey)
	if auth.ID == "" {
		auth.ID = IDFromPublicKey(pubkey)
	}

	//auth.VIP6 = Pub2VIP(auth.PublicKey)
	//auth.VIP64 = auth.NodeIDUInt(auth.PublicKey)
	// Based on the primary EC256 key

	return auth
}

// mesh certificates - new style
const (
	WorkloadCertDir = "/var/run/secrets/workload-spiffe-credentials"

	// Different from typical Istio  and CertManager key.pem - we can check both
	privateKey = "private_key.pem"

	WorkloadRootCAs = "ca-certificates.crt"

	// Also different, we'll check all. CertManager uses cert.pem
	cert = "certificates.pem"

	// This is derived from CA certs plus all TrustAnchors.
	// In GKE, it is expected that Citadel roots will be configure using TrustConfig - so they are visible
	// to all workloads including TD proxyless GRPC.
	//
	// Outside of GKE, this is loaded from the mesh.env - the mesh gate is responsible to keep it up to date.
	rootCAs = "ca_certificates.pem"

	legacyCertDir = "/etc/certs"
)

var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// IDFromPublicKey returns a node WorkloadID based on the
// public key of the node - 52 bytes base32.
func IDFromPublicKey(key crypto.PublicKey) string {
	m := MarshalPublicKey(key)
	if len(m) > 32 {
		sha256 := sha256.New()
		sha256.Write(m)
		m = sha256.Sum([]byte{}) // 302
	}
	return enc.EncodeToString(m)
}

func IDFromPublicKeyBytes(m []byte) string {
	if len(m) > 32 {
		sha256 := sha256.New()
		sha256.Write(m)
		m = sha256.Sum([]byte{}) // 302
	}
	return enc.EncodeToString(m)
}

func IDFromCert(c []*x509.Certificate) string {
	if c == nil || len(c) == 0 {
		return ""
	}
	key := c[0].PublicKey
	m := MarshalPublicKey(key)
	if len(m) > 32 {
		sha256 := sha256.New()
		sha256.Write(m)
		m = sha256.Sum([]byte{}) // 302
	}
	return enc.EncodeToString(m)
}

// Host2ID concerts a Host/:authority or path parameter hostname to a node ID.
func (auth *MeshAuth) Host2ID(host string) string {
	col := strings.Index(host, ".")
	if col > 0 {
		host = host[0:col]
	} else {
		col = strings.Index(host, ":")
		if col > 0 {
			host = host[0:col]
		}
	}
	return strings.ToUpper(host)
}

// Will load the credentials and create an Auth object.
//
// This uses pilot-agent or some other platform tool creating ./var/run/secrets/istio.io/{key,cert-chain}.pem
// or /var/run/secrets/workload-spiffe-credentials
func (a *MeshAuth) SetKeysDir(dir string) error {
	a.CertDir = dir
	err := a.waitAndInitFromDir()
	if err != nil {
		return err
	}
	return nil
}

func (a *MeshAuth) SetKeysPEM(privatePEM []byte, chainPEM []string) error {
	chainPEMCat := strings.Join(chainPEM, "\n")
	tlsCert, err := tls.X509KeyPair([]byte(chainPEMCat), privatePEM)
	if err != nil {
		return err
	}
	if tlsCert.Certificate == nil || len(tlsCert.Certificate) == 0 {
		return errors.New("missing certificate")
	}

	return a.SetTLSCertificate(&tlsCert)
}

func (a *MeshAuth) SetTLSCertificate(cert *tls.Certificate) error {
	a.Cert = cert
	a.initFromCert()
	return nil
}

func (a *MeshAuth) leaf() *x509.Certificate {
	if a.Cert == nil {
		return nil
	}
	if a.Cert.Leaf == nil {
		a.Cert.Leaf, _ = x509.ParseCertificate(a.Cert.Certificate[0])
	}
	return a.Cert.Leaf
}

// GetCertificate is typically called during handshake, both server and client.
// "sni" will be empty for client certificates, and set for server certificates - if not set, workload id is returned.
//
// ctx is the handshake context - may include additional metadata about the operation.
func (a *MeshAuth) GetCertificate(ctx context.Context, sni string) (*tls.Certificate, error) {
	// TODO: if host != "", allow returning DNS certs for the host.
	// Default (and currently only impl) is to return the spiffe cert
	// May refresh.

	// Have cert, not expired
	if a.Cert != nil {
		if !a.leaf().NotAfter.Before(time.Now()) {
			return a.Cert, nil
		}
	}

	if a.CertDir != "" {
		c, err := a.loadCertFromDir(a.CertDir)
		if err == nil {
			if !c.Leaf.NotAfter.Before(time.Now()) {
				a.Cert = c
			}
		} else {
			log.Println("Cert from dir failed", err)
		}
	}

	if a.GetCertificateHook != nil {
		c, err := a.GetCertificateHook(sni)
		if err != nil {
			return nil, err
		}
		a.Cert = c
	}

	if a.Cert == nil {
		return &tls.Certificate{}, nil
	}
	return a.Cert, nil
}

func (a *MeshAuth) loadCertFromDir(dir string) (*tls.Certificate, error) {
	// Load cert from file
	keyFile := filepath.Join(dir, "key.pem")
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		keyFile = filepath.Join(dir, privateKey)
		keyBytes, err = ioutil.ReadFile(keyFile)
	}
	if err != nil {
		return nil, err
	}
	certBytes, err := ioutil.ReadFile(filepath.Join(dir, "cert-chain.pem"))
	if err != nil {
		certBytes, err = ioutil.ReadFile(filepath.Join(dir, cert))
	}
	if err != nil {
		return nil, err
	}

	tlsCert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, err
	}

	if tlsCert.Certificate == nil || len(tlsCert.Certificate) == 0 {
		return nil, errors.New("missing certificate")
	}
	tlsCert.Leaf, _ = x509.ParseCertificate(tlsCert.Certificate[0])

	return &tlsCert, nil
}

func (a *MeshAuth) waitAndInitFromDir() error {
	if a.CertDir == "" {
		a.CertDir = "./var/run/secrets/istio.io/"
	}
	keyFile := filepath.Join(a.CertDir, "key.pem")
	err := waitFile(keyFile, 5*time.Second)
	if err != nil {
		return err
	}

	err = a.initFromDir()
	if err != nil {
		return err
	}

	return nil
}

func (a *MeshAuth) initFromDirPeriodic() {
	err := a.initFromDir()
	if err != nil {
		log.Println("certRefresh", err)
	}
	time.AfterFunc(30*time.Minute, a.initFromDirPeriodic)
}

func (a *MeshAuth) initFromDir() error {
	if a.Cert == nil {
		_, err := a.GetCertificate(context.Background(), "")
		if err != nil {
			return err
		}
	}

	rootCert, _ := ioutil.ReadFile(filepath.Join(a.CertDir, "root-cert.pem"))
	if rootCert != nil {
		err2 := a.AddRoots(rootCert)
		if err2 != nil {
			return err2
		}
	}

	istioCert, _ := ioutil.ReadFile("./var/run/secrets/istio/root-cert.pem")
	if istioCert != nil {
		err2 := a.AddRoots(istioCert)
		if err2 != nil {
			return err2
		}
	}

	// Similar with /etc/ssl/certs/ca-certificates.crt - the concatenated list of PEM certs.
	rootCertExtra, _ := ioutil.ReadFile(filepath.Join(a.CertDir, WorkloadRootCAs))
	if rootCertExtra != nil {
		err2 := a.AddRoots(rootCertExtra)
		if err2 != nil {
			return err2
		}
	}

	// If the certificate has a chain, use the last cert - similar with Istio
	if a.Cert != nil && len(a.Cert.Certificate) > 1 {
		last := a.Cert.Certificate[len(a.Cert.Certificate)-1]

		a.AddRootDER(last)
	}

	if a.Cert != nil {
		a.initFromCert()
	}
	time.AfterFunc(30*time.Minute, a.initFromDirPeriodic)
	return nil
}

// Return the SPKI fingerprint of the key
// https://www.rfc-editor.org/rfc/rfc7469#section-2.4
//
// Can be used with "ignore-certificate-errors-spki-list" in chrome
//
//	openssl x509 -pubkey -noout -in <path to PEM cert> | openssl pkey -pubin -outform der \
//	  | openssl dgst -sha256 -binary | openssl enc -base64
//
// sha256/BASE64
func SPKIFingerprint(key crypto.PublicKey) string {
	// pubDER, err := x509.MarshalPKIXPublicKey(c.PublicKey.(*rsa.PublicKey))
	d := MarshalPublicKey(key)
	sum := sha256.Sum256(d)
	pin := make([]byte, base64.StdEncoding.EncodedLen(len(sum)))
	base64.StdEncoding.Encode(pin, sum[:])
	return string(pin)
}

// Convert a PublicKey to a marshalled format - in the raw format.
// - 32 byte ED25519
// - 65 bytes EC256 ( 0x04 prefix )
// - DER RSA key (PKCS1)
//
// Normally the key is available from request or response TLS.PeerCertificate[0]
func MarshalPublicKey(key crypto.PublicKey) []byte {
	if k, ok := key.(ed25519.PublicKey); ok {
		return []byte(k)
	}
	if k, ok := key.(*ecdsa.PublicKey); ok {
		return elliptic.Marshal(elliptic.P256(), k.X, k.Y)
		// starts with 0x04 == uncompressed curve
	}
	if k, ok := key.(*rsa.PublicKey); ok {
		bk := x509.MarshalPKCS1PublicKey(k)
		return bk
	}
	if k, ok := key.([]byte); ok {
		if len(k) == 64 || len(k) == 32 {
			return k
		}
	}

	return nil
}

// MarshalPrivateKey returns the PEM encoding of the key
func MarshalPrivateKey(priv crypto.PrivateKey) []byte {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		encodedKey := x509.MarshalPKCS1PrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: blockTypeRSAPrivateKey, Bytes: encodedKey})
	case *ecdsa.PrivateKey:
		encodedKey, _ := x509.MarshalECPrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: blockTypeECPrivateKey, Bytes: encodedKey})
	case *ed25519.PrivateKey:
	}
	// TODO: ed25529

	return nil
}

// SaveCerts will create certificate files as expected by gRPC and Istio, similar with the
// auto-created files.
//
// This creates 3 files.
// NGinx and others also support one file, in the order cert, intermediary, key,
// and using hostname as the name.
func (a *MeshAuth) SaveCerts(outDir string) error {
	if outDir == "" {
		outDir = WorkloadCertDir
	}
	err := os.MkdirAll(outDir, 0755)
	// TODO: merge other roots as needed - this is Istio XDS server root.
	rootFile := filepath.Join(outDir, WorkloadRootCAs)
	if err != nil {
		return err
	}

	rootsB := bytes.Buffer{}
	for _, k := range a.RootCertificates {
		pemb := pem.EncodeToMemory(&pem.Block{Type: blockTypeCertificate, Bytes: k})
		rootsB.Write(pemb)
		rootsB.Write([]byte{'\n'})
	}

	err = ioutil.WriteFile(rootFile, rootsB.Bytes(), 0644)
	if err != nil {
		return err
	}

	keyFile := filepath.Join(outDir, privateKey)
	chainFile := filepath.Join(outDir, cert)
	os.MkdirAll(outDir, 0755)

	p := MarshalPrivateKey(a.Cert.PrivateKey)

	// TODO: full chain
	bb := bytes.Buffer{}
	for _, crt := range a.Cert.Certificate {
		b := pem.EncodeToMemory(
			&pem.Block{
				Type:  blockTypeCertificate,
				Bytes: crt,
			},
		)
		bb.Write(b)
	}

	err = ioutil.WriteFile(keyFile, p, 0660)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(chainFile, bb.Bytes(), 0660)
	if err != nil {
		return err
	}
	if os.Getuid() == 0 {
		os.Chown(outDir, 1337, 1337)
		os.Chown(keyFile, 1337, 1337)
		os.Chown(chainFile, 1337, 1337)
	}

	return nil
}

// Common setup for cert management.
// After the 'mesh-env' is loaded (from env, k8s, URL) the next step is to init the workload identity.
// This must happen before connecting to XDS - since certs is one of the possible auth methods.
//
// The logic is:
//   - (best case) certificates already provisioned by platform. Detects GKE paths (CAS), old Istio, CertManager style
//     If workload certs are platform-provisioned: extract trust domain, namespace, name, pod id from cert.
//
// - Detect the WORKLOAD_SERVICE_ACCOUNT, trust domain from JWT or mesh-env
// - Use WORKLOAD_CERT json to load the config for the CSR, create a CSR
// - Call CSRSigner.
// - Save the certificates if running as root or an output dir is set. This will use CAS naming convention.
//
// If envoy + pilot-agent are used, they should be configured to use the cert files.
// This is done by setting "CA_PROVIDER=GoogleGkeWorkloadCertificate" when starting pilot-agent
func (kr *MeshAuth) InitCertificates(ctx context.Context, certDir string) error {
	if certDir == "" {
		certDir = WorkloadCertDir
	}
	var err error
	keyFile := filepath.Join(certDir, privateKey)
	chainFile := filepath.Join(certDir, cert)
	privPEM, err := ioutil.ReadFile(keyFile)
	certPEM, err := ioutil.ReadFile(chainFile)

	kp, err := tls.X509KeyPair(certPEM, privPEM)
	if err == nil && len(kp.Certificate) > 0 {
		kr.CertDir = certDir

		kp.Leaf, _ = x509.ParseCertificate(kp.Certificate[0])

		exp := kp.Leaf.NotAfter.Sub(time.Now())
		if exp > -5*time.Minute {
			kr.Cert = &kp
			log.Println("Existing Cert", "expires", exp)
			return nil
		}
	}
	return nil
}

// Extract the trustDomain, namespace and Name from a spiffee certificate
func (a *MeshAuth) Spiffee() (*url.URL, string, string, string) {
	cert, err := x509.ParseCertificate(a.Cert.Certificate[0])
	if err != nil {
		return nil, "", "", ""
	}
	if len(cert.URIs) > 0 {
		c0 := cert.URIs[0]
		pathComponetns := strings.Split(c0.Path, "/")
		if c0.Scheme == "spiffe" && pathComponetns[1] == "ns" && pathComponetns[3] == "sa" {
			return c0, c0.Host, pathComponetns[2], pathComponetns[4]
		}
	}
	return nil, "", "", ""
}

func (a *MeshAuth) WorkloadID() string {
	su, _, _, _ := a.Spiffee()
	return su.String()
}

func (a *MeshAuth) String() string {
	cert, err := x509.ParseCertificate(a.Cert.Certificate[0])
	if err != nil {
		return ""
	}
	id := ""
	if len(cert.URIs) > 0 {
		id = cert.URIs[0].String()
	}
	return fmt.Sprintf("WorkloadID=%s,iss=%s,exp=%v,org=%s", id, cert.Issuer,
		cert.NotAfter, cert.Subject.Organization)
}

// Add a list of certificates in DER format to the root.
func (a *MeshAuth) AddRootDER(root []byte) error {
	rootCAs, err := x509.ParseCertificates(root)
	a.RootCertificates = append(a.RootCertificates, root)
	if err == nil {
		for _, c := range rootCAs {
			a.trustedCertPool.AddCert(c)
		}
	}
	return err
}

// AddRoots will process a PEM file containing multiple concatenated certificates.
func (a *MeshAuth) AddRoots(rootCertPEM []byte) error {
	block, rest := pem.Decode(rootCertPEM)
	//var blockBytes []byte
	for block != nil {
		a.AddRootDER(block.Bytes)
		block, rest = pem.Decode(rest)
	}
	return nil
}

func (a *MeshAuth) GenerateTLSConfigClient(name string) *tls.Config {
	return a.GenerateTLSConfigClientRoots(name, nil)
}

// GenerateTLSConfigClient will provide mesh client certificate config.
// TODO: SecureNaming or expected SANs
func (a *MeshAuth) GenerateTLSConfigClientRoots(name string, pool *x509.CertPool) *tls.Config {
	return &tls.Config{
		//MinVersion: tls.VersionTLS13,
		//PreferServerCipherSuites: ugate.preferServerCipherSuites(),

		ServerName: name,
		GetCertificate: func(ch *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return a.GetCertificate(ch.Context(), ch.ServerName)
		},

		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return a.GetCertificate(cri.Context(), "")
		},
		NextProtos: []string{"h2"},

		InsecureSkipVerify: true, // This is not insecure here. We will verify the cert chain ourselves.
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return a.verifyServerCert(name, rawCerts, verifiedChains, pool)
		},
	}
}
func (a *MeshAuth) VerifyServerCert(rawCerts [][]byte, all [][]*x509.Certificate) error {
	return a.verifyServerCert("", rawCerts, all, nil)
}

// Verify the server certificate. The client TLS context is called with InsecureSkipVerify,
// so 'normal' verification is disabled - only rawCerts are available.
//
// Will check:
// - certificate is valid
// - if it has a Spiffee identity - verify it is in same namespace or istio-system
// - else: verify it matches SNI (unless sni is empty). For DNS only will use provided pool or root certs
func (a *MeshAuth) verifyServerCert(sni string, rawCerts [][]byte, _ [][]*x509.Certificate, pool *x509.CertPool) error {
	if len(rawCerts) == 0 {
		return errors.New("client certificate required")
	}
	var peerCert *x509.Certificate
	intCertPool := x509.NewCertPool()

	for id, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return err
		}
		if id == 0 {
			peerCert = cert
		} else {
			intCertPool.AddCert(cert)
		}
	}
	if peerCert == nil || len(peerCert.URIs) == 0 && len(peerCert.DNSNames) == 0 {
		return errors.New("peer certificate does not contain URI or DNS SANs")
	}
	if len(peerCert.URIs) > 0 {
		c0 := peerCert.URIs[0]

		// Verify the trust domain of the peer's is same.
		// TODO: aliases
		trustDomain := c0.Host
		if trustDomain != a.TrustDomain {
			log.Println("MTLS: invalid trust domain", trustDomain, peerCert.URIs)
			return errors.New("invalid trust domain " + trustDomain + " " + a.TrustDomain)
		}

		if pool == nil {
			pool = a.trustedCertPool
		}
		_, err := peerCert.Verify(x509.VerifyOptions{
			Roots:         pool,
			Intermediates: intCertPool,
		})
		if err != nil {
			return err
		}

		parts := strings.Split(c0.Path, "/")
		if len(parts) < 4 {
			log.Println("MTLS: invalid path", peerCert.URIs)
			return errors.New("invalid path " + c0.String())
		}

		ns := parts[2]
		if ns == "istio-system" || ns == a.Namespace {
			return nil
		}

		return nil
	} else {
		// No DomainName since we verified spiffee
		if pool == nil {
			_, err := peerCert.Verify(x509.VerifyOptions{
				Roots:         nil, // use system
				Intermediates: intCertPool,
			})
			if err != nil {
				_, err = peerCert.Verify(x509.VerifyOptions{
					Roots:         a.trustedCertPool,
					Intermediates: intCertPool,
				})
			}
			if err != nil {
				return err
			}
		} else {
			_, err := peerCert.Verify(x509.VerifyOptions{
				Roots:         pool,
				Intermediates: intCertPool,
			})
			if err != nil {
				return err
			}
		}
		if sni == "" {
			return nil
		}

		if len(peerCert.DNSNames) > 0 {
			err := peerCert.VerifyHostname(sni)
			if err == nil {
				return nil
			}
		}
		//for _, n := range peerCert.DNSNames {
		//	if n == sni {
		//		return nil
		//	}
		//}
		for _, n := range peerCert.IPAddresses {
			if n.String() == sni {
				return nil
			}
		}
		// DNS certificate - need to verify the name separatedly.
		return errors.New("dns cert not found " + sni)
	}
}

func (a *MeshAuth) VerifyClientCert(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		log.Println("MTLS: missing client cert")
		return errors.New("client certificate required")
	}
	var peerCert *x509.Certificate
	intCertPool := x509.NewCertPool()

	for id, rawCert := range rawCerts {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return err
		}
		if id == 0 {
			peerCert = cert
		} else {
			intCertPool.AddCert(cert)
		}
	}
	if peerCert == nil || len(peerCert.URIs) == 0 {
		log.Println("MTLS: missing URIs in Istio cert", peerCert)
		return errors.New("peer certificate does not contain URI type SAN")
	}
	c0 := peerCert.URIs[0]
	trustDomain := c0.Host
	if trustDomain != a.TrustDomain {
		log.Println("MTLS: invalid trust domain", trustDomain, peerCert.URIs)
		return errors.New("invalid trust domain " + trustDomain + " " + a.TrustDomain)
	}

	_, err := peerCert.Verify(x509.VerifyOptions{
		Roots:         a.trustedCertPool,
		Intermediates: intCertPool,
	})
	if err != nil {
		return err
	}

	parts := strings.Split(c0.Path, "/")
	if len(parts) < 4 {
		log.Println("MTLS: invalid path", peerCert.URIs)
		return errors.New("invalid path " + c0.String())
	}

	ns := parts[2]
	if ns == "istio-system" || ns == a.Namespace {
		return nil
	}

	// TODO: also validate namespace is same with this workload or in list of namespaces ?
	if len(a.AllowedNamespaces) == 0 {
		log.Println("MTLS: namespace not allowed", peerCert.URIs)
		return errors.New("Namespace not allowed")
	}

	if a.AllowedNamespaces[0] == "*" {
		return nil
	}

	for _, ans := range a.AllowedNamespaces {
		if ns == ans {
			return nil
		}
	}

	log.Println("MTLS: namespace not allowed", peerCert.URIs)
	return errors.New("Namespace not allowed")
}

// GenerateTLSConfigServer is used to provide the server tls.Config for handshake.
// Will use the workload identity and do basic checks on client certs.
func (a *MeshAuth) GenerateTLSConfigServer() *tls.Config {
	return &tls.Config{
		//MinVersion: tls.VersionTLS13,
		//PreferServerCipherSuites: ugate.preferServerCipherSuites(),
		InsecureSkipVerify: true,                  // This is not insecure here. We will verify the cert chain ourselves.
		ClientAuth:         tls.RequestClientCert, // not require - we'll fallback to JWT

		GetCertificate: func(ch *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return a.GetCertificate(ch.Context(), ch.ServerName)
		},

		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			// The server can include a list of 'acceptable CAs' - as list of DER-encoded DN
			return a.GetCertificate(cri.Context(), "")
		},

		// Will check the peer certificate, using the trust roots.
		VerifyPeerCertificate: a.VerifyClientCert,

		NextProtos: []string{"istio", "h2"},
	}
}

// initFromCert initializes the MeshTLSConfig with the workload certificate
func (a *MeshAuth) initFromCert() {
	_, a.TrustDomain, a.Namespace, a.Name = a.Spiffee()

	a.MeshTLSConfig = a.GenerateTLSConfigServer()
}

// waitFile will check for the file to show up - the agent is running in a separate process.
func waitFile(keyFile string, d time.Duration) error {
	t0 := time.Now()
	var err error
	for {
		// Wait for key file to show up - pilot agent creates it.
		if _, err := os.Stat(keyFile); os.IsNotExist(err) {
			if time.Since(t0) > d {
				return err
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return nil
	}

	return err
}

// SetVapid sets a new Vapid generator from EC256 public and private keys,
// in base64 uncompressed format.
func (v *MeshAuth) SetVapid(publicKey64, privateKey64 string) {
	publicUncomp, _ := base64.RawURLEncoding.DecodeString(publicKey64)
	privateUncomp, _ := base64.RawURLEncoding.DecodeString(privateKey64)

	x, y := elliptic.Unmarshal(elliptic.P256(), publicUncomp)
	d := new(big.Int).SetBytes(privateUncomp)
	pubkey := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	pkey := ecdsa.PrivateKey{PublicKey: pubkey, D: d}

	tlsCert, _, _ := v.generateSelfSigned("ec256", &pkey, "TODO")
	// Required now

	v.PublicKeyBase64 = publicKey64
	v.PublicKey = publicUncomp
	v.Priv = privateUncomp
	v.PublicKey = elliptic.Marshal(elliptic.P256(), pkey.X, pkey.Y)
	v.Priv = pkey.D.Bytes()
	v.Cert = &tlsCert
}

// Generate and save the primary self-signed Certificate
func (auth *MeshAuth) generateSelfSigned(prefix string, priv crypto.PrivateKey, sans ...string) (tls.Certificate, []byte, []byte) {
	return auth.SignCert(priv, priv, sans...)
}

func (auth *MeshAuth) SignCert(priv crypto.PrivateKey, ca crypto.PrivateKey, sans ...string) (tls.Certificate, []byte, []byte) {
	pub := PublicKey(priv)
	certDER := auth.SignCertDER(pub, ca, sans...)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	ecb, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecb})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Println("Error generating cert ", err)
	}
	return tlsCert, keyPEM, certPEM
}

func (auth *MeshAuth) SignCertDER(pub crypto.PublicKey, caPrivate crypto.PrivateKey, sans ...string) []byte {
	var notBefore time.Time
	notBefore = time.Now().Add(-1 * time.Hour)

	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   sans[0],
			Organization: []string{auth.TrustDomain},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              sans,
		//IPAddresses:           []net.IP{auth.VIP6},
	}
	// IPFS:
	//certKeyPub, err := x509.MarshalPKIXPublicKey(certKey.Public())
	//signature, err := sk.Sign(append([]byte(certificatePrefix), certKeyPub...))
	//value, err := asn1.Marshal(signedKey{
	//	PubKey:    keyBytes,
	//	Signature: signature,
	//})

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, caPrivate)
	if err != nil {
		panic(err)
	}
	return certDER
}

var useED = false

// initSelfSigned will load a cert from env, and if not found create a new self-signed cert.
func (auth *MeshAuth) initSelfSigned(kty string) {

	if auth.Cert != nil {
		return // got a cert
	}
	//var keyPEM, certPEM []byte
	var tlsCert tls.Certificate
	if kty == "ed25519" {
		_, edpk, _ := ed25519.GenerateKey(rand.Reader)
		auth.PubID = IDFromPublicKey(PublicKey(edpk))
		tlsCert, _, _ = auth.generateSelfSigned("ed25519", edpk, auth.Name+"."+auth.TrustDomain)
		auth.Cert = &tlsCert
	} else if kty == "rsa" {
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		tlsCert, _, _ := auth.generateSelfSigned("rsa", priv, auth.Name+"."+auth.TrustDomain)
		auth.Cert = &tlsCert
	} else {
		privk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		auth.PubID = IDFromPublicKey(PublicKey(privk))
		tlsCert, _, _ = auth.generateSelfSigned("ec256", privk, auth.Name+"."+auth.TrustDomain)
		auth.Cert = &tlsCert
	}
}

func (auth *MeshAuth) NodeID() []byte {
	return auth.VIP6[8:]
}

var (
	MESH_NETWORK = []byte{0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0, 0x00}
)

// Convert a public key to a VIP. This is the primary WorkloadID of the nodes.
// Primary format is the 64-byte EC256 public key.
//
// For RSA, the ASN.1 format of the byte[] is used.
// For ED, the 32-byte raw encoding.
func Pub2VIP(pub []byte) net.IP {
	if pub == nil {
		return nil
	}
	ip6 := make([]byte, 16)
	copy(ip6, MESH_NETWORK)

	binary.BigEndian.PutUint64(ip6[8:], Pub2ID(pub))
	return net.IP(ip6)
}

// Return the self identity. Currently it's using the VIP6 format - may change.
// This is used in Message 'From' and in ReqContext.
func (a *MeshAuth) Self() string {
	return a.VIP6.String()
}

// Generate a 8-byte identifier from a public key
func Pub2ID(pub []byte) uint64 {
	if len(pub) > 65 {
		sha256 := sha1.New()
		sha256.Write(pub)
		keysha := sha256.Sum([]byte{}) // 302
		return binary.BigEndian.Uint64(keysha[len(keysha)-8:])
	} else {
		// For EC256 and ED - for now just the last bytes
		return binary.BigEndian.Uint64(pub[len(pub)-8:])
	}
}

func (auth *MeshAuth) NodeIDUInt(pub []byte) uint64 {
	return Pub2ID(pub)
}

// OIDC discovery on .well-known/openid-configuration
func (a *MeshAuth) HandleDisc(w http.ResponseWriter, r *http.Request) {
	// Issuer must match the hostname used to connect.
	//
	w.Header().Set("content-type", "application/json")
	fmt.Fprintf(w, `{
  "issuer": "https://%s",
  "jwks_uri": "https://%s/jwks",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "ES256"
  ]
}`, r.Host, r.Host)

	// ,"EdDSA"
	// TODO: switch to EdDSA
}

// OIDC JWK
func (a *MeshAuth) HandleJWK(w http.ResponseWriter, r *http.Request) {
	pk := a.Cert.PrivateKey.(*ecdsa.PrivateKey)
	byteLen := (pk.Params().BitSize + 7) / 8
	ret := make([]byte, byteLen)
	pk.X.FillBytes(ret[0:byteLen])
	x64 := base64.RawURLEncoding.EncodeToString(ret[0:byteLen])
	pk.Y.FillBytes(ret[0:byteLen])
	y64 := base64.RawURLEncoding.EncodeToString(ret[0:byteLen])
	fmt.Fprintf(w, `{
  "keys": [
    {
		 "kty" : "EC",
		 "crv" : "P-256",
		 "x"   : "%s",
		 "y"   : "%s",
    }
  ]
	}`, x64, y64)

	//		"crv": "Ed25519",
	//		"kty": "OKP",
	//		"x"   : "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
}

// Sign - requires ECDSA primary key
func (auth *MeshAuth) Sign(data []byte, sig []byte) {
	hasher := crypto.SHA256.New()
	hasher.Write(data) //[0:64]) // only public key, for debug
	hash := hasher.Sum(nil)

	c0 := auth.Cert
	if ec, ok := c0.PrivateKey.(*ecdsa.PrivateKey); ok {
		r, s, _ := ecdsa.Sign(rand.Reader, ec, hash)
		copy(sig, r.Bytes())
		copy(sig[32:], s.Bytes())
	} else if ed, ok := c0.PrivateKey.(ed25519.PrivateKey); ok {
		sig1, _ := ed.Sign(rand.Reader, hash, nil)
		copy(sig, sig1)
	}
}

var (
	oidExtensionSubjectAltName = []int{2, 5, 29, 17}
)

const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

func getSANExtension(c *x509.Certificate) []byte {
	for _, e := range c.Extensions {
		if e.Id.Equal(oidExtensionSubjectAltName) {
			return e.Value
		}
	}
	return nil
}

func GetSAN(c *x509.Certificate) ([]string, error) {
	extension := getSANExtension(c)
	dns := []string{}
	// RFC 5280, 4.2.1.6

	// SubjectAltName ::= GeneralNames
	//
	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	//
	// GeneralName ::= CHOICE {
	//      otherName                       [0]     OtherName,
	//      rfc822Name                      [1]     IA5String,
	//      dNSName                         [2]     IA5String,
	//      x400Address                     [3]     ORAddress,
	//      directoryName                   [4]     Name,
	//      ediPartyName                    [5]     EDIPartyName,
	//      uniformResourceIdentifier       [6]     IA5String,
	//      iPAddress                       [7]     OCTET STRING,
	//      registeredID                    [8]     OBJECT IDENTIFIER }
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return dns, err
	} else if len(rest) != 0 {
		return dns, errors.New("x509: trailing data after X.509 extension")
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return dns, asn1.StructuralError{Msg: "bad SAN sequence"}
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return dns, err
		}

		if v.Tag == nameTypeDNS {
			dns = append(dns, string(v.Bytes))
		}
	}
	return dns, nil
}

// Get all known certificates from local files. This is used to support
// lego certificates and istio.
//
// "istio" is a special name, set if istio certs are found
func (auth *MeshAuth) GetCerts() map[string]*tls.Certificate {
	certMap := map[string]*tls.Certificate{}

	if _, err := os.Stat("./etc/certs/key.pem"); !os.IsNotExist(err) {
		crt, err := tls.LoadX509KeyPair("./etc/certs/cert-chain.pem", "./etc/certs/key.pem")
		if err != nil {
			log.Println("Failed to load system istio certs", err)
		} else {
			certMap["istio"] = &crt
			if crt.Leaf != nil {
				log.Println("Loaded istio cert ", crt.Leaf.URIs)
			}
		}
	}

	legoBase := os.Getenv("HOME") + "/.lego/certificates"
	files, err := ioutil.ReadDir(legoBase)
	if err == nil {
		for _, ff := range files {
			s := ff.Name()
			if strings.HasSuffix(s, ".key") {
				s = s[0 : len(s)-4]
				base := legoBase + "/" + s
				cert, err := tls.LoadX509KeyPair(base+".crt",
					base+".key")
				if err != nil {
					log.Println("ACME: Failed to load ", s, err)
				} else {
					certMap[s] = &cert
					log.Println("ACME: Loaded cert for ", s)
				}
			}
		}
	}

	return certMap
}

func RawToCertChain(rawCerts [][]byte) ([]*x509.Certificate, error) {
	chain := make([]*x509.Certificate, len(rawCerts))
	for i := 0; i < len(rawCerts); i++ {
		cert, err := x509.ParseCertificate(rawCerts[i])
		if err != nil {
			return nil, err
		}
		chain[i] = cert
	}
	return chain, nil
}

// PubKeyFromCertChain verifies the certificate chain and extract the remote's public key.
func PubKeyFromCertChain(chain []*x509.Certificate) (crypto.PublicKey, error) {
	if chain == nil || len(chain) == 0 {

	}
	cert := chain[0]

	// Self-signed certificate
	if len(chain) == 1 {
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		if _, err := cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
			// If we return an x509 error here, it will be sent on the wire.
			// Wrap the error to avoid that.
			return nil, fmt.Errorf("certificate verification failed: %s", err)
		}
	} else {
		//
		pool := x509.NewCertPool()
		pool.AddCert(chain[len(chain)-1])
		if _, err := cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
			// If we return an x509 error here, it will be sent on the wire.
			// Wrap the error to avoid that.
			return nil, fmt.Errorf("chain certificate verification failed: %s", err)
		}
	}

	// IPFS uses a key embedded in a custom extension, and verifies the public key of the cert is signed
	// with the node public key

	// This transport is instead based on standard certs/TLS

	key := cert.PublicKey
	if ec, ok := key.(*ecdsa.PublicKey); ok {
		return ec, nil
	}
	if rsak, ok := key.(*rsa.PublicKey); ok {
		return rsak, nil
	}
	if ed, ok := key.(ed25519.PublicKey); ok {
		return ed, nil
	}

	return nil, errors.New("unknown public key")
}
