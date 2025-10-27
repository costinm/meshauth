package certs

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"path/filepath"
	"time"
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


// newRoot initializes the root CA.
func (ca *Certs) newRoot() {
	cal := GenerateKey("")
	caCert, caCertPEM := rootCert(ca.FQDN, "", "rootCA", cal, cal, nil)
	ca.Private = cal
	ca.CACert = caCert
	ca.CACertPEM = caCertPEM
}

// SetCert will init CA from PEM bytes. For example loading it from a
// K8S Secret or files.
func (ca *Certs) SetCert(privPEM, certPEM []byte) error {
	kp, err := tls.X509KeyPair(certPEM, privPEM)
	if err != nil {
		return err
	}

	kp.Leaf, _ = x509.ParseCertificate(kp.Certificate[0])
	ca.CACertPEM = certPEM
	ca.CACert = kp.Leaf

	ca.Private = kp.PrivateKey

	cn := ca.CACert.Subject.Organization[0]
	ca.FQDN = cn

	return nil
}

func (ca *Certs) Init(dir string) error {
	privPEM, err := ioutil.ReadFile(filepath.Join(dir, keyFile))
	if err != nil {
		return err
	}
	certPEM, err := ioutil.ReadFile(filepath.Join(dir, chainFile))
	if err != nil {
		return err
	}
	ca.LoadTime = time.Now()
	return ca.SetCert(privPEM, certPEM)
}

// Save will save:
// - private key as tls.key (PEM)
// - CA certificate as ca.pem
// - certificate chain
func (ca *Certs) Save(ctx context.Context, dir string) error {
	p := MarshalPrivateKeyPEM(ca.Private)

	err := ioutil.WriteFile(filepath.Join(dir, keyFile), p, 0660)
	if err != nil {
		return err
	}

	if ca.CACertPEM != nil {
		// This is the self-signed cert, to be used as a root of trust.
		err = ioutil.WriteFile(filepath.Join(dir, chainFile), ca.CACertPEM, 0660)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(filepath.Join(dir, caCrt), ca.CACertPEM, 0660)
		if err != nil {
			return err
		}
	} else {
		err = ioutil.WriteFile(filepath.Join(dir, chainFile), ca.IntermediatesPEM, 0660)
		if err != nil {
			return err
		}

		// TODO: if we don't have a caCrt file, save the last key in the
		// intermediate chain as root (usually good enough).

	}



	return nil
}


func (ca *Certs) NewID(ns, sa string, dns []string) *Cert {
	_, kp, cp := ca.NewTLSCert(ns, sa, dns)
	c := NewCert()
	c.SetCertPEM(string(kp), string(cp))
	return c
}

// CertManager - intermediary certs have tls.key, tls.crt (std k8s)
// plus ca.crt for the root CA. All certs issued with private CAs
// have ca.crt - a CA cert is like any other cert.

// In istio: istio-ca-secret in istio-system used to have ca-cert.pem, ca-key.pem, ca.crt
// However new versions use tls.key, tls.crt

const keyFile = "tls.key"
const chainFile = "tls.crt"
const caCrt  = "ca.crt"

// NewIntermediaryCA creates a cert for an intermediary CA.
func (ca *Certs) NewIntermediaryCA(trust, cluster string) *Certs {
	cak := GenerateKey("")

	caCert, caCertPEM := rootCert(trust, cluster, "rootCA", cak, ca.Private, ca.CACert)

	caCertPEM = append(caCertPEM, ca.CACertPEM...)
	// TODO: add some restrictions or meta to indicate the cluster

	return &Certs{Private: cak, CACert: caCert, CACertPEM: caCertPEM,
		FQDN: trust,
	}
}


//var GenerateKey = GenerateKey
//var PublicKey = PublicKey

// NewTLSCert creates a new cert from this CA.
func (ca *Certs) NewTLSCert(ns, sa string, dns []string) (*tls.Certificate, []byte, []byte) {
	nodeKey := GenerateKey("")

	urlsan := ""
	if ns != "" {
		urlsan = "spiffe://" + ca.FQDN + "/ns/" +ns+"/sa/"+sa
	}

	crt := &Cert{

	}

	csr := crt.CertTemplate(ca.FQDN, urlsan, dns...)

	return ca.newTLSCertAndKey(csr, nodeKey, ca.Private, ca.CACert)
}

// SignCertDER uses caPrivate to sign a tlsCrt, returns the DER format.
// Used primarily for tests with self-signed tlsCrt.
func SignCertDER(template *x509.Certificate, pub crypto.PublicKey, caPrivate crypto.PrivateKey, parent *x509.Certificate) ([]byte, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, caPrivate)
	if err != nil {
		return nil, err
	}
	return certDER, nil
}

// rootCert creates a CA certificate.
// If parent and ca are set, the cert is signed by parent.
// Otherwise, it is a top, self-signed certificate.
func rootCert(org, ou, cn string, priv crypto.PrivateKey, ca crypto.PrivateKey, parent *x509.Certificate) (*x509.Certificate, []byte) {

	pub := PublicKey(priv)

	var notBefore time.Time
	notBefore = time.Now().Add(-1 * time.Hour)

	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)

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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: BlockTypeCertificate, Bytes: certDER})

	return rootCA[0], certPEM
}

func (c *Certs) newTLSCertAndKey(template *x509.Certificate, priv crypto.PrivateKey, ca crypto.PrivateKey, parent *x509.Certificate) (*tls.Certificate, []byte, []byte) {
	pub := PublicKey(priv)

	certDER, err := SignCertDER(template, pub, ca, parent)
	if err != nil {
		return nil, nil, nil
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: BlockTypeCertificate, Bytes: certDER})

	if c.IntermediatesPEM != nil {
		certPEM = append(certPEM, c.IntermediatesPEM...)
	}

	// Add intermediate CA, if any and the root - for istio compat and to allow
	// checking the chain using root SHA
	certPEM = append(certPEM, c.CACertPEM...)

	ecb, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: BlockTypePKCS8PrivateKey, Bytes: ecb})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, nil
	}

	return &tlsCert, keyPEM, certPEM
}

// Signs and return a PEM-encoded certificate.
// The result includes the root CACertPEM files (intermediaries),
// but does not include the CA root or other trusted CAs.
func (c *Certs) SignCertificate(template *x509.Certificate, pub crypto.PublicKey) (string) {

	certDER, err := SignCertDER(template, pub, c.Private, c.CACert)
	if err != nil {
		return ""
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: BlockTypeCertificate, Bytes: certDER})

	// Add intermediate CA, if any and the root - for istio compat and to allow
	// checking the chain using root SHA
	certPEM = append(certPEM, c.IntermediatesPEM...)

	return string(certPEM)
}

