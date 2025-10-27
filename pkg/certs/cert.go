package certs

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Certificate is DER encoded stuct containing a []byte, algorithm (oid) and
// BitString signature ([]byte, starting with padding len).
// The first array is typically a X508 sequence.

// A Cert is a private key and an associated certificate chain.
//
// The certificate chain includes X509 signatures on the public
// key and associated data, and is equivalent with a signed token.
//
// A Cert can issue and verify tokens.
type Cert struct {
	// Cert is the loaded certificate.
	*tls.Certificate `json:"-"`

	// Org will be set in the CN field - should be the TrustDomain for mesh.
	Org string

	Name string
	Domain string

	DNSSANs []string
	SPIFFE  string

	CA bool

	// If Base is set, cert will be loaded, and error generated if missing.
	// If not set and no other initialization is performed, a
	// self-signed certificate is generated.
	Base string `json:"base,omitempty"`

	// Certificates signing the private key.
	// First is the cert signing the public key, followed by any
	// certs signing previous certs. It is not required to include to
	// 'top level' root that signed the entire chain (which should be
	// in the trust roots).
	ChainPEM []byte `json:"chainPEM,omitempty"`
	KeyPEM []byte `json:"keyPEM,omitempty"`
}

func NewCert() *Cert {
	return &Cert{}
}


func (cert *Cert) Provision(ctx context.Context) error {
	if cert.Certificate == nil {
		privk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		crt, keyPEM, certPEM := cert.SignCert(privk, privk)

		cert.Certificate = &crt
		cert.KeyPEM = keyPEM
		cert.ChainPEM = certPEM

	}

	return nil
}


// TLSClientConf returns a TLS config using this certificate as
// client cert
//
// sni can override the cluster sni
// remotePub32 is the cert-baseed identity of a specific endpoint.
//
// On the returned config, you can override "NextProtos" (defaults
//  to h2), and ServerName (defaults to the dest FQDN)
func (cert *Cert) TLSClientConf(dest *Trust, sni string,
		remotePub32 string, rootT *MeshTrust) *tls.Config {

	pool := rootT.certPool //  a.trustedCertPool
	if dest.CACertPEM != "" {
		pool = dest.certPool
	}
	// We need to check the peer WorkloadID in the VerifyPeerCertificate callback.
	// The tls.Config it is also used for listening, and we might also have concurrent dials.
	// Clone it so we can check for the specific peer WorkloadID we're dialing here.
	conf := &tls.Config{
		// This is not insecure here. We will verify the remote pub in VerifyPeerCertificate.
		InsecureSkipVerify: true, // dest.InsecureSkipTLSVerify, // || remotePub32 != "" ||
		//len(dest.URLSANs) > 0 ||
		//len(dest.DNSSANs) > 0,

		// If dest specifies a pool - use it.
		// Else use the mesh pool
		RootCAs: pool,

		// provide the workload cert if asked
		Certificates:           []tls.Certificate{*cert.Certificate},
		NextProtos:             []string{"h2"},
		ServerName:             sni,
		SessionTicketsDisabled: false,
		ClientSessionCache:     dest.ClientSessionCache,

		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cert.Certificate, nil
			//return mesh.GetCertificate(cri.Context(), "")
		},
	}

	if len(dest.URLSANs) > 0 || len(dest.DNSSANs) > 0  || remotePub32 != ""{
		conf.InsecureSkipVerify = true
		conf.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {

			return dest.verifyServerCert(sni, rawCerts, verifiedChains, pool,
				remotePub32)
		}
	}
	return conf
}

// GenerateTLSConfigServer is used to provide the server tls.Config for handshakes.
//
// Will use the workload identity and do basic checks on client certs.
// It does not require client certs - but asks for them, and if found verifies.
//
// If allowMeshExternal is set, will skip verification for certs with different
// trust domain.
//
// The GetCertificate method can be replaced with one that handles
// multiple domains.
func (cert *Cert) GenerateTLSConfigServer(trust *MeshTrust) *tls.Config {
	// TODO: setting to allow use of public CAs for server checking clients
	cfg := &tls.Config{
		//MinVersion: tls.VersionTLS13,
		//PreferServerCipherSuites: ugate.preferServerCipherSuites(),
		InsecureSkipVerify: true,                  // This is not insecure here. We will verify the cert chain ourselves.
		ClientAuth:         tls.RequestClientCert, // not require - we'll fallback to JWT
		ClientCAs:          trust.certPool,
		GetCertificate: func(ch *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Will only be called if client supplies SNI and Certificates empty
			// Requested ALPN info is lost after handshake.
			//log.Println("Server/NewConn/CH",
			//	"sni", ch.ServerName,
			//	"alpn", ch.SupportedProtos,
			//	"local", ch.Conn.LocalAddr(),
			//	"remote", ch.Conn.RemoteAddr())

			// Serve the requested cert if a SNI name is present and we have
			// a cert. Else serve the workload cert.
			return cert.Certificate, nil // mesh.GetCertificate(ch.Context(), ch.ServerName)
		},

		// Will check the peer certificate, using the trust roots.
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return trust.VerifyClientCert(trust.AllowMeshExternal, rawCerts, verifiedChains)
		},

		NextProtos: []string{"h2"},
	}
	return cfg
}



// GenerateTLSConfigDest returns a custom tls config for a Dest and a context holder.
// This should be used with a single
func (cert *Cert) TLSClient(ctx context.Context, nc net.Conn,
		dest *Trust, mt *MeshTrust,
		remotePub32 string) (*tls.Conn, error) {
	tlsc := tls.Client(nc,
		cert.TLSClientConf(dest, "", remotePub32, mt))

	if err := tlsc.HandshakeContext(ctx); err != nil {
		// if the context was canceled, return the context error
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}

	return tlsc, nil
}



func (cert *Cert) InitSelfSignedPEMKey(keyPEM string) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block != nil {
		if block.Type == "EC PRIVATE KEY" {
			privk, _ := x509.ParseECPrivateKey(block.Bytes)
			cert.InitSelfSignedKey(privk)
		}
	}
}

func (cert *Cert) InitSelfSignedKey(privk crypto.PrivateKey) {

}

// Leaf returns the leaf certificate from the loaded cert, or a new template based on the Cert fields.
func (cert *Cert) Leaf() *x509.Certificate {
	if cert.Certificate == nil {
		return nil
	}
	if cert.Certificate.Leaf == nil {
		cert.Certificate.Leaf, _ = x509.ParseCertificate(cert.Certificate.Certificate[0])
	}
	return cert.Certificate.Leaf
}

func (cert *Cert) PrivateKeyPEM() string {
	return string(MarshalPrivateKeyPEM(cert.Certificate.PrivateKey))
}

func (cert *Cert) PublicKeyPEM() string {
	return string(MarshalPublicKey(cert.Leaf().PublicKey))
}

// SignCert will create a tls.Certificate and the PEM encoding of the
// certificate, using the fields in Cert.
func (cert *Cert) SignCert(priv crypto.PrivateKey, ca crypto.PrivateKey, sans ...string) (tls.Certificate, []byte, []byte) {

	pub := PublicKey(priv)

	certDER := cert.SignCertDER(pub, ca, sans...)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	ecb, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecb})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Println("Error generating cert ", err)
	}
	return tlsCert, keyPEM, certPEM
}

func (cert *Cert) SignCertDER(pub crypto.PublicKey, caPrivate crypto.PrivateKey, sans ...string) []byte {

	var notBefore time.Time
	notBefore = time.Now().Add(-1 * time.Hour)

	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   sans[0],
			Organization: []string{cert.Org},
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


func (ca *Cert) CertTemplate(org string, urlSAN string, sans ...string) *x509.Certificate {
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



func (cert *Cert) SetCertPEM(privatePEM string, chainPEMCat string) error {
	tlsCert, err := tls.X509KeyPair([]byte(chainPEMCat), []byte(privatePEM))
	if err != nil {
		return err
	}
	if tlsCert.Certificate == nil || len(tlsCert.Certificate) == 0 {
		return errors.New("missing certificate")
	}

	cert.Certificate = &tlsCert

	cert.ChainPEM = []byte(chainPEMCat)
	return nil
}

func (cert *Cert) Save(ctx context.Context, dir string) error {
	p := MarshalPrivateKeyPEM(cert.Certificate.PrivateKey)

	_ = os.Mkdir(dir, 0750)

	err := ioutil.WriteFile(filepath.Join(dir, keyFile), p, 0660)
	if err != nil {
		return err
	}

	if cert.ChainPEM == nil {
		// if cert.Certificate was set directly.
		// TODO: full chain
		bb := bytes.Buffer{}
		for _, crt := range cert.Certificate.Certificate {
			b := pem.EncodeToMemory(
				&pem.Block{
					Type:  BlockTypeCertificate,
					Bytes: crt,
				},
			)
			bb.Write(b)
		}
		cert.ChainPEM = bb.Bytes()
	}
	err = ioutil.WriteFile(filepath.Join(dir, chainFile), cert.ChainPEM, 0660)
	if err != nil {
		return err
	}
	return nil

}



// Extract the trustDomain, namespace and Name from a spiffee certificate
func (cert *Cert) Spiffee() (*url.URL, string, string, string) {
	xcert, err := x509.ParseCertificate(cert.Certificate.Certificate[0])
	if err != nil {
		return nil, "", "", ""
	}
	if len(xcert.URIs) > 0 {
		c0 := xcert.URIs[0]
		pathComponetns := strings.Split(c0.Path, "/")
		if c0.Scheme == "spiffe" && pathComponetns[1] == "ns" && pathComponetns[3] == "sa" {
			return c0, c0.Host, pathComponetns[2], pathComponetns[4]
		}
	}
	return nil, "", "", ""
}



func (cert *Cert) PubB32() string {
	return PublicKeyBase32SHA(PublicKey(cert.PrivateKey))
}

func (cert *Cert) PublicKey() []byte {
	return MarshalPublicKey(PublicKey(cert.PrivateKey))
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
