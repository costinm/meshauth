package certs

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"time"
)

type Cert struct {
	// Cert is the loaded certificate.
	*tls.Certificate

	// Org will be set in the CN field - should be the TrustDomain for mesh.
	Org string

	DNSSANs []string
	SPIFFE string

	CA bool

}

func NewCert() *Cert {
	return &Cert{}
}



func (mesh *Cert) InitSelfSignedPEMKey(keyPEM string) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block != nil {
		if block.Type == "EC PRIVATE KEY" {
			privk, _ := x509.ParseECPrivateKey(block.Bytes)
			mesh.InitSelfSignedKey(privk)
		}
	}
}

func (mesh *Cert) InitSelfSignedKey(privk crypto.PrivateKey) {

}

// Leaf returns the leaf certificate from the loaded cert, or a new template based on the Cert fields.
func (mesh *Cert) Leaf() *x509.Certificate {
	if mesh.Certificate == nil {
		return nil
	}
	if mesh.Certificate.Leaf == nil {
		mesh.Certificate.Leaf, _ = x509.ParseCertificate(mesh.Certificate.Certificate[0])
	}
	return mesh.Certificate.Leaf
}

func (mesh *Cert) PrivateKeyPEM() string {
	return string(MarshalPrivateKey(mesh.Certificate.PrivateKey))
}

func (mesh *Cert) PublicKeyPEM() string {
	return string(MarshalPublicKey(mesh.Leaf().PublicKey))
}

func (mesh *Cert) SignCert(priv crypto.PrivateKey, ca crypto.PrivateKey, sans ...string) (tls.Certificate, []byte, []byte) {
	pub := PublicKey(priv)
	certDER := mesh.SignCertDER(pub, ca, sans...)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	ecb, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecb})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Println("Error generating cert ", err)
	}
	return tlsCert, keyPEM, certPEM
}

func (mesh *Cert) SignCertDER(pub crypto.PublicKey, caPrivate crypto.PrivateKey, sans ...string) []byte {
	var notBefore time.Time
	notBefore = time.Now().Add(-1 * time.Hour)

	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   sans[0],
			Organization: []string{mesh.Org},
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

type Trust struct {
	Domain string
	Namespace           string
	RootCertificatesDER [][]byte `json:"roots,omitempty"`

	CertPool *x509.CertPool
}


// Add a list of certificates in DER format to the root.
// The top signer of the workload certificate is added by default.
func (mesh *Trust) AddRootDER(root []byte) error {
	rootCAs, err := x509.ParseCertificates(root)
	//mesh.RootCertificatesDER = append(mesh.RootCertificatesDER, root)
	if err == nil {
		for _, c := range rootCAs {
			mesh.CertPool.AddCert(c)
			mesh.RootCertificatesDER = append(mesh.RootCertificatesDER, c.Raw)
		}
	}
	return err
}

// AddRoots will process a PEM file containing multiple concatenated certificates.
func (mesh *Trust) AddRoots(rootCertPEM []byte) error {
	block, rest := pem.Decode(rootCertPEM)
	for block != nil {
		mesh.AddRootDER(block.Bytes)
		block, rest = pem.Decode(rest)
	}
	return nil
}

func (mesh *Trust) RootsPEM() string {
	rootsB := bytes.Buffer{}
	for _, k := range mesh.RootCertificatesDER {
		pemb := pem.EncodeToMemory(&pem.Block{Type: BlockTypeCertificate, Bytes: k})
		rootsB.Write(pemb)
		rootsB.Write([]byte{'\n'})
	}
	return string(rootsB.Bytes())
}
