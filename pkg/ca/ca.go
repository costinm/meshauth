package ca

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
	"math/big"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/costinm/meshauth"
)

// CA deals with certificate management.
//
// Istio CA interface is very flexible - it takes a 'CSR' string and
// returns a list of 'certificates' - but the input can be anything,
// including empty, and the output can also include concatenated PEM
// files. The use of metadata (headers) makes it even more flexible.
//
// So an implementation of the gRPC API could decide to accept empty
// CSR and generate keys, or use input as a hostname and return key
// and certificates. Envoy (and others) can also map it to JSON.
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

	// Private key for the CA.
	Private crypto.PrivateKey

	// CACert is the associated cert.
	CACert *x509.Certificate

	TrustDomain string

	// The Certificate may be signed by multiple intermediaries
	IntermediatesPEM []byte

	// Root certs that signed the root.
	CACertPEM []byte
}

// NewCA creates a new CA. Keys must be loaded.
func NewCA(cfg *meshauth.Mesh) *CA {
	ca := &CA{}
	ca.TrustDomain = "cluster.local"
	return ca
}


// NewTempCA creates a temporary/test CA.
func NewTempCA(trust string) *CA {
	if trust == "" {
		trust = "cluster.local"
	}
	cao := &CA{TrustDomain: trust}
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
	p := meshauth.MarshalPrivateKey(ca.Private)

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
	}
}

// New ID creates a new Mesh, with a certificate signed by this CA
//
// The cert will include both Spiffe identiy and DNS SANs.
func (ca *CA) NewID(ns, sa string, dns []string) *meshauth.Mesh {
	_, kp, cp := ca.NewTLSCert(ns, sa, dns)

	nodeID := meshauth.New(&meshauth.MeshCfg{})
	nodeID.AddRoots(ca.CACertPEM)
	// Will fill in trust domain, namespace, sa from the minted cert.
	nodeID.SetCertPEM(string(kp), string(cp))
	//nodeID.setTLSCertificate(crt)

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

// NewTLSCert creates a new cert from this CA.
func (ca *CA) NewTLSCert(ns, sa string, dns []string) (*tls.Certificate, []byte, []byte) {
	nodeKey := generateKey("")
	csr := ca.CertTemplate(ca.TrustDomain, "spiffe://" + ca.TrustDomain + "/ns/" +ns+"/sa/"+sa, dns...)

	return ca.newTLSCertAndKey(csr, nodeKey, ca.Private, ca.CACert)
}

// signCertDER uses caPrivate to sign a tlsCrt, returns the DER format.
// Used primarily for tests with self-signed tlsCrt.
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

func (a *CA) GetToken(ctx context.Context, sub, aud, iss string) (string, error) {
	jwt := &meshauth.JWT{
		Aud: []string{aud},
		Exp: time.Now().Add(1 * time.Hour).Unix(),
		Sub: sub,
		Iss: iss,
	}
	return jwt.Sign(a.Private), nil
}

// OIDC JWKS handler - returns the
func (a *CA) HandleJWK(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(a.GetJWK()))
}

func (a *CA) GetJWK() string {

	pk := a.Private.(*ecdsa.PrivateKey)
	byteLen := (pk.Params().BitSize + 7) / 8
	ret := make([]byte, byteLen)
	pk.X.FillBytes(ret[0:byteLen])
	x64 := base64.RawURLEncoding.EncodeToString(ret[0:byteLen])
	pk.Y.FillBytes(ret[0:byteLen])
	y64 := base64.RawURLEncoding.EncodeToString(ret[0:byteLen])
	return fmt.Sprintf(`{"keys":[{"kty": "EC","crv": "P-256","x": "%s","y": "%s"}]}`, x64, y64)

	//		"crv": "Ed25519",
	//		"kty": "OKP",
	//		"x"   : "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
}

func (ca *CA) CertTemplate(org string, urlSAN string, sans ...string) *x509.Certificate {
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

func (c *CA) SignCertificate(template *x509.Certificate, pub crypto.PublicKey) (string) {

	certDER, err := signCertDER(template, pub, c.Private, c.CACert)
	if err != nil {
		return ""
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: blockTypeCertificate, Bytes: certDER})

	// Add intermediate CA, if any and the root - for istio compat and to allow
	// checking the chain using root SHA
	certPEM = append(certPEM, c.CACertPEM...)

	return string(certPEM)
}


const (
	blockTypeECPrivateKey      = "EC PRIVATE KEY"
	blockTypeRSAPrivateKey   = "RSA PRIVATE KEY" // PKCS#1 private key
	blockTypePKCS8PrivateKey = "PRIVATE KEY"     // PKCS#8 plain private key
	blockTypeCertificate     = "CERTIFICATE"
)

