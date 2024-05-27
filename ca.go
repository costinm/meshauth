package meshauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	blockTypeECPrivateKey    = "EC PRIVATE KEY"
	blockTypeRSAPrivateKey   = "RSA PRIVATE KEY" // PKCS#1 private key
	blockTypePKCS8PrivateKey = "PRIVATE KEY"     // PKCS#8 plain private key
	blockTypeCertificate     = "CERTIFICATE"
)

type CAConfig struct {
	// TrustDomain to use in certs.
	// Should not be 'cluster.local' - but a real FQDN
	TrustDomain string

	// Location of the CA root - currently a dir path.
	//
	RootLocation string

	// TODO: additional configs/policies.
}

// CA is used as an internal CA, mainly for testing and provisioning.
// Roughly equivalent with a simplified Istio Citadel.
//
// Istio CA uses 2 kinds of roots:
// - direct - using istio-ca-secret.istio-system secret
// - intermediate - using cacerts.istio-system
//
// Istio used to stores the files in /etc/cacerts - there are 3 or 4 files:
// ca-key.pem - root or intermediary key
// ca-cert.pem - single certificate associated with ca-key.
// cert-chain.pem - will be appended to all generated certificates - should be a chain path to the root, not including ca-cert
// ca-cert.pem - the root key (top root)
//
// More recent versions of Istio are compatible with CertManager.
type CA struct {
	Config *CAConfig

	Private crypto.PrivateKey

	CACert *x509.Certificate

	TrustDomain string
	prefix      string

	IntermediatesPEM []byte

	// Root certs
	CACertPEM []byte

	KeyType string

	ExtraKeyProvider func(public interface{}, id string, secret *Secret)
}

// NewCA creates a new CA. Keys must be loaded.
func NewCA(cfg *CAConfig) *CA {
	ca := &CA{Config: cfg}
	if cfg.TrustDomain == "" {
		cfg.TrustDomain = "cluster.local"
	}
	ca.prefix = "spiffe://" + cfg.TrustDomain + "/ns/"
	return ca
}

// NewTempCA creates a temporary/test CA.
func NewTempCA(trust string) *CA {
	if trust == "" {
		trust = "cluster.local"
	}
	cao := &CA{TrustDomain: trust, Config: &CAConfig{TrustDomain: trust}}
	cao.NewRoot()
	return cao
}

// NewRoot initializes the root CA.
func (ca *CA) NewRoot() {
	cal := generateKey("")
	caCert, caCertPEM := rootCert(ca.TrustDomain, "", "rootCA", cal, cal, nil)
	ca.Private = cal
	ca.CACert = caCert
	ca.CACertPEM = caCertPEM
	ca.prefix = "spiffe://" + ca.TrustDomain + "/ns/"
}

// SetCert will Init an existing root CA from bytes.
func (ca *CA) SetCert(privPEM, certPEM []byte) error {
	kp, err := tls.X509KeyPair(certPEM, privPEM)
	if err != nil {
		return err
	}

	kp.Leaf, _ = x509.ParseCertificate(kp.Certificate[0])
	ca.CACertPEM = certPEM
	ca.CACert = kp.Leaf

	ca.Private = kp.PrivateKey
	cn := ca.CACert.Subject.Organization[0]
	ca.TrustDomain = cn
	ca.prefix = "spiffe://" + cn + "/ns/"

	// TODO: set trust, prefix from the loaded CA.

	return nil
}

func (ca *CA) Init(dir string) error {
	privPEM, err := ioutil.ReadFile(filepath.Join(dir, keyFile))
	if err != nil {
		return err
	}
	certPEM, err := ioutil.ReadFile(filepath.Join(dir, chainFile))
	if err != nil {
		return err
	}
	return ca.SetCert(privPEM, certPEM)
}

func (ca *CA) Save(dir string) error {
	p := MarshalPrivateKey(ca.Private)

	err := ioutil.WriteFile(filepath.Join(dir, keyFile), p, 0660)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filepath.Join(dir, chainFile), ca.CACertPEM, 0660)
	if err != nil {
		return err
	}
	return nil
}

func CAFromEnv(dir string) *CA {
	trust := os.Getenv("TRUST_DOMAIN")

	ca := NewCA(&CAConfig{TrustDomain: trust, RootLocation: dir})

	err := ca.Init(dir)
	if err != nil {
		log.Fatal(err)
	}

	return ca
}

// CertManager - intermediary certs have tls.key, tls.crt (std k8s)
// plus ca.crt for the root CA. All certs issued with private CAs
// have ca.crt - a CA cert is like any other cert.

// In istio: istio-ca-secret in istio-system used to have ca-cert.pem, ca-key.pem, ca.crt
// However new versions use tls.key, tls.crt
const keyFile = "tls.key"
const chainFile = "tls.crt"

// NewIntermediaryCA creates a cert for an intermediary CA.
func (ca *CA) NewIntermediaryCA(trust, cluster string) *CA {
	cak := generateKey("")

	caCert, caCertPEM := rootCert(trust, cluster, "rootCA", cak, ca.Private, ca.CACert)

	caCertPEM = append(caCertPEM, ca.CACertPEM...)
	// TODO: add some restrictions or meta to indicate the cluster

	return &CA{Private: cak, CACert: caCert, CACertPEM: caCertPEM,
		TrustDomain: trust,
		prefix:      "spiffe://" + trust + "/ns/",
	}
}

// New ID creates a new MeshAuth, with a certificate signed by this CA
//
// The cert will include both Spiffe identiy and DNS SANs.
func (ca *CA) NewID(ns, sa string, dns []string) *MeshAuth {
	crt, kp, cp := ca.NewTLSCert(ns, sa, dns)

	nodeID := NewMeshAuth(&MeshCfg{})
	nodeID.AddRoots(ca.CACertPEM)
	// Will fill in trust domain, namespace, sa from the minted cert.
	nodeID.SetCertPEM(string(kp), string(cp))
	nodeID.SetTLSCertificate(crt)

	return nodeID
}

var kty = "ec266"

func generateKey(kty string) crypto.PrivateKey {
	if kty == "ed25519" {
		_, edpk, _ := ed25519.GenerateKey(rand.Reader)
		return edpk
	} else if kty == "rsa" {
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		return priv
	}
	privk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	return privk
}

// NewCertificate returns a Secret including certificates and optionally a private key.
//
// # WIP
//
// If the request has a public key, it will be used for the certs.
//
// V3: further simplification, certificates are just a APIserver extension using Secret as interface.
// The cert is reflected from the request authentication.
// Clients don't have any control (expected to be config-less) - the server policy decides.
func (ca *CA) NewCertificate(w http.ResponseWriter, r *http.Request) {
	// Must be wrapped in an auth handler that sets the context
	// TODO: for sign, implement K8S cert signing interface - or get public from self-signed cert.

}

// NewTLSCert creates a new cert from this CA.
func (ca *CA) NewTLSCert(ns, sa string, dns []string) (*tls.Certificate, []byte, []byte) {
	nodeKey := generateKey("")
	csr := certTemplate(ca.TrustDomain, ca.prefix+ns+"/sa/"+sa, dns...)

	return ca.newTLSCertAndKey(csr, nodeKey, ca.Private, ca.CACert)
}

//func (a *MeshAuth) NewCSR(san string) (privPEM []byte, csrPEM []byte, err error) {
//	var priv crypto.PrivateKey
//
//	rsaKey := generateKey("")
//	priv = rsaKey
//
//	csr := &x509.CertificateRequest{
//		Subject: pkix.Name{
//			Organization: []string{san},
//		},
//	}
//	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, priv)
//
//	encodeMsg := "CERTIFICATE REQUEST"
//
//	csrPEM = pem.EncodeToMemory(&pem.Block{Type: encodeMsg, Bytes: csrBytes})
//
//	var encodedKey []byte
//	switch k := priv.(type) {
//	case *rsa.PrivateKey:
//		encodedKey = x509.MarshalPKCS1PrivateKey(k)
//		privPEM = pem.EncodeToMemory(&pem.Block{Type: blockTypeRSAPrivateKey, Bytes: encodedKey})
//	case *ecdsa.PrivateKey:
//		encodedKey, err = x509.MarshalECPrivateKey(k)
//		if err != nil {
//			return nil, nil, err
//		}
//		privPEM = pem.EncodeToMemory(&pem.Block{Type: blockTypeECPrivateKey, Bytes: encodedKey})
//	}
//
//	return
//}

// signCertDER uses caPrivate to sign a cert, returns the DER format.
// Used primarily for tests with self-signed cert.
func signCertDER(template *x509.Certificate, pub crypto.PublicKey, caPrivate crypto.PrivateKey, parent *x509.Certificate) ([]byte, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, caPrivate)
	if err != nil {
		return nil, err
	}
	return certDER, nil
}

func PublicKey(key crypto.PrivateKey) crypto.PublicKey {
	if k, ok := key.(ed25519.PrivateKey); ok {
		return k.Public()
	}
	if k, ok := key.(*ecdsa.PrivateKey); ok {
		return k.Public()
	}
	if k, ok := key.(*rsa.PrivateKey); ok {
		return k.Public()
	}

	return nil
}

func (a *CA) GetToken(ctx context.Context, aud string) (string, error) {
	jwt := &JWT{
		Aud: []string{aud},
	}
	return jwt.Sign(a.Private), nil
}

// OIDC JWKS handler - returns the
func (a *CA) HandleJWK(w http.ResponseWriter, r *http.Request) {
	pk := a.Private.(*ecdsa.PrivateKey)
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

func certTemplate(org string, urlSAN string, sans ...string) *x509.Certificate {
	var notBefore time.Time
	notBefore = time.Now().Add(-1 * time.Hour)

	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		//IPAddresses:           []net.IP{auth.VIP6},
	}
	if urlSAN != "" {
		u, err := url.Parse(urlSAN)
		if err == nil {
			template.URIs = []*url.URL{u}
		}
	}
	if len(sans) > 0 {
		template.Subject.CommonName = sans[0]
	}

	for _, k := range sans {
		if strings.Contains(k, "://") {
			u, _ := url.Parse(k)
			template.URIs = append(template.URIs, u)
		} else {
			template.DNSNames = append(template.DNSNames, k)
		}
	}
	// IPFS:
	//certKeyPub, err := x509.MarshalPKIXPublicKey(certKey.Public())
	//signature, err := sk.Sign(append([]byte(certificatePrefix), certKeyPub...))
	//value, err := asn1.Marshal(signedKey{
	//	PubKey:    keyBytes,
	//	Signature: signature,
	//})
	return &template
}

func rootCert(org, ou, cn string, priv crypto.PrivateKey, ca crypto.PrivateKey, parent *x509.Certificate) (*x509.Certificate, []byte) {
	pub := PublicKey(priv)
	var notBefore time.Time
	notBefore = time.Now().Add(-1 * time.Hour)

	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	if ou != "" {
		template.Subject.OrganizationalUnit = []string{ou}
	}
	if parent == nil {
		parent = &template
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, parent, pub, ca)
	if err != nil {
		panic(err)
	}

	rootCA, err := x509.ParseCertificates(certDER)
	if err != nil {
		panic(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: blockTypeCertificate, Bytes: certDER})

	return rootCA[0], certPEM
}

func (c *CA) newTLSCertAndKey(template *x509.Certificate, priv crypto.PrivateKey, ca crypto.PrivateKey, parent *x509.Certificate) (*tls.Certificate, []byte, []byte) {
	pub := PublicKey(priv)
	certDER, err := signCertDER(template, pub, ca, parent)
	if err != nil {
		return nil, nil, nil
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: blockTypeCertificate, Bytes: certDER})

	if c.IntermediatesPEM != nil {
		certPEM = append(certPEM, c.IntermediatesPEM...)
	}

	// Add intermediate CA, if any and the root - for istio compat and to allow
	// checking the chain using root SHA
	certPEM = append(certPEM, c.CACertPEM...)

	ecb, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: blockTypePKCS8PrivateKey, Bytes: ecb})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, nil
	}

	return &tlsCert, keyPEM, certPEM
}
