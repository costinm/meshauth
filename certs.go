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

	"github.com/costinm/meshauth/pkg/certs"
)

// Certificates are typically used with TLS and mTLS, but the key is the primary
// key of the workload.
// This file has code related to loading and processing certs.
// The end result is Mesh.Cert

// TLS notes:
// - using HandshakeContext with custom verification for workload identity (spiffe)
//   - instead of x509.VerifyOptions{DNSName} - based on ServerName from the config, which
//     can be overriden by client.
//
// - native library also supports nested TLS - if the RoundTripStart method is overriden and scheme is https,
//    it will do a TLS handshake anyway and RoundTripStart can implement TLS for the outer tunnel.


// Certificate is DER encoded stuct containing a []byte, algorithm (oid) and
// BitString signature ([]byte, first is padding len).
//

// initFromCert initializes the MeshTLSConfig with the workload certificate
// Called after a.Cert has been set.
func (mesh *Mesh) initFromCert() {
	if mesh.Cert == nil {
		return
	}
	_, td, ns, n := mesh.Spiffee()
	if mesh.Domain == "" {
		mesh.Domain = td
	}
	if mesh.Namespace == "" {
		mesh.Namespace = ns
	}
	if mesh.Name == "" {
		mesh.Name = n
	}

	publicKey := mesh.leaf().PublicKey
	mesh.PublicKey = certs.MarshalPublicKey(publicKey)
	if mesh.Priv == "" {
		mesh.Priv = string(MarshalPrivateKey(mesh.Cert.PrivateKey))
	}


	mesh.VIP6 = Pub2VIP(mesh.PublicKey)
	mesh.VIP64 = mesh.NodeIDUInt(mesh.PublicKey)
	// Based on the primary EC256 key
	if mesh.ID == "" {
		mesh.ID = PublicKeyBase32SHA(publicKey)
	}

	// Setting a cert also implies trusting it's signer.
	if mesh.Cert != nil && len(mesh.Cert.Certificate) > 1 {
		last := mesh.Cert.Certificate[len(mesh.Cert.Certificate)-1]

		mesh.AddRootDER(last)
	}
}

func (mesh *Mesh) PubID32() string {
	return PublicKeyBase32SHA(PublicKey(mesh.leaf().PublicKey))
}

// Will init the Cert, PubID, PublicKey fields - private is in Cert.
func (mesh *Mesh) InitSelfSigned(kty string) *Mesh {
	if mesh.Cert != nil {
		return mesh // got a cert
	}



	//var keyPEM, certPEM []byte
	var tlsCert tls.Certificate
	if kty == "ed25519" {
		_, edpk, _ := ed25519.GenerateKey(rand.Reader)
		tlsCert, _, _ = mesh.generateSelfSigned("ed25519", edpk, mesh.Name+"."+mesh.Domain)
	} else if kty == "rsa" {
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		tlsCert, _, _ = mesh.generateSelfSigned("rsa", priv, mesh.Name+"."+mesh.Domain)
	} else {
		privk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tlsCert, _, _ = mesh.generateSelfSigned("ec256", privk, mesh.Name+"."+mesh.Domain)
	}
	mesh.setTLSCertificate(&tlsCert)
	return mesh
}

func (mesh *Mesh) InitSelfSignedKeyRaw(privk crypto.PrivateKey) error {
	tlsCert, _, _ := mesh.generateSelfSigned("ec256", privk, mesh.Name+"."+mesh.Domain)
	mesh.setTLSCertificate(&tlsCert)
	//mesh.Priv = kty

	return nil
}

// InitSelfSignedFromPEMKey will use the private key (EC PEM) and generate a self
// signed certificate, using the config (name.domain)
func (mesh *Mesh) InitSelfSignedFromPEMKey(keyPEM string) error {
	// Use pre-defined private key
	block, _ := pem.Decode([]byte(keyPEM))
	if block != nil {
		if block.Type == "EC PRIVATE KEY" {
			privk, _ := x509.ParseECPrivateKey(block.Bytes)
			tlsCert, _, _ := mesh.generateSelfSigned("ec256", privk, mesh.Name+"."+mesh.Domain)
			mesh.setTLSCertificate(&tlsCert)
			return nil
		}
	}

	return nil
}

func RawKeyToPrivateKey(key, pub string) *ecdsa.PrivateKey {
	publicUncomp, _ := base64.RawURLEncoding.DecodeString(pub)
	privateUncomp, _ := base64.RawURLEncoding.DecodeString(key)

	// TODO: privateUncomp may be DER ?
	x, y := elliptic.Unmarshal(elliptic.P256(), publicUncomp)
	d := new(big.Int).SetBytes(privateUncomp)
	pubkey := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	pkey := ecdsa.PrivateKey{PublicKey: pubkey, D: d}

	return &pkey
}

// mesh certificates - new style
const (
	varRunSecretsWorkloadSpiffeCredentials = "/var/run/secrets/workload-spiffe-credentials"

	// Different from typical Istio  and CertManager key.pem - we can check both
	//privateKey = "private_key.pem"
	//workloadRootCAs = "ca-certificates.crt"
	// Also different, we'll check all. CertManager uses cert.pem
	//cert = "certificates.pem"

	// CertManager-style file names. Used as default certs when saving and loading
	caCrt  = "ca.crt"
	tlsKey = "tls.key"
	tlsCrt = "tls.crt"

	// This is derived from CA certs plus all TrustAnchors.
	// In GKE, it is expected that Citadel roots will be configure using TrustConfig - so they are visible
	// to all workloads including TD proxyless GRPC.
	//
	// Outside of GKE, this is loaded from the mesh.env - the mesh gate is responsible to keep it up to date.
	rootCAs = "ca_certificates.pem"

	etcCerts = "/etc/certs"
)

var base32Enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// --------------- Helpers and methods --------------

// PublicKeyBase32SHA returns a node WorkloadID based on the
// public key of the node - 52 bytes base32 for EC256 keys
func PublicKeyBase32SHA(key crypto.PublicKey) string {
	m := MarshalPublicKey(key)
	if len(m) > 32 {
		sha256 := sha256.New()
		sha256.Write(m)
		m = sha256.Sum([]byte{}) // 302
	}
	// ED key is sent as-is
	return base32Enc.EncodeToString(m)
}


// Host2ID converts a Host/:authority or path parameter hostname to a node ID.
func (mesh *Mesh) Host2ID(host string) string {
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

// SetCertPEM explicitly set the certificate and key. The cert will not be rotated - use a dir to reload
// or call this function with fresh certs before it expires.
func (mesh *Mesh) SetCertPEM(privatePEM string, chainPEMCat string) error {
	tlsCert, err := tls.X509KeyPair([]byte(chainPEMCat), []byte(privatePEM))
	if err != nil {
		return err
	}
	if tlsCert.Certificate == nil || len(tlsCert.Certificate) == 0 {
		return errors.New("missing certificate")
	}

	return mesh.setTLSCertificate(&tlsCert)
}

func (mesh *Mesh) setTLSCertificate(cert *tls.Certificate) error {
	mesh.Cert = cert
	mesh.initFromCert()
	return nil
}

func (mesh *Mesh) leaf() *x509.Certificate {
	if mesh.Cert == nil {
		return nil
	}
	if mesh.Cert.Leaf == nil {
		mesh.Cert.Leaf, _ = x509.ParseCertificate(mesh.Cert.Certificate[0])
	}
	return mesh.Cert.Leaf
}

// GetCertificate is typically called during handshake, both server and client.
// "sni" will be empty for client certificates, and set for server certificates - if not set, workload id is returned.
//
// ctx is the handshake context - may include additional metadata about the operation.
func (mesh *Mesh) GetCertificate(ctx context.Context, sni string) (*tls.Certificate, error) {
	// TODO: if host != "", allow returning DNS certs for the host.
	// Default (and currently only impl) is to return the spiffe cert
	// May refresh.
	// doesn't include :5228
	// Have cert, not expired
	if sni == "" {
		if mesh.Cert != nil {
			if !mesh.leaf().NotAfter.Before(time.Now()) {
				return mesh.Cert, nil
			}
		}

		if mesh.ConfigLocation != "" {
			c, _, err := loadCertFromDir(mesh.ConfigLocation)
			if err == nil {
				if mesh.Cert == nil || !c.Leaf.NotAfter.Before(time.Now()) {
					mesh.Cert = c
				}
			}
			return c, nil
		}
		return nil, nil
	}

	if mesh.CertMap == nil {
		mesh.CertMap = mesh.GetCerts()
	}
	c, ok := mesh.CertMap[sni]
	if ok {
		return c, nil
	}

	if mesh.GetCertificateHook != nil {
		c, err := mesh.GetCertificateHook(sni)
		if err != nil {
			return nil, err
		}
		mesh.Cert = c
	}

	if mesh.Cert == nil {
		return &tls.Certificate{}, nil
	}

	return mesh.Cert, nil
}

// loadCertFromDir will attempt to read from a tlsCrt directory, attempting well-known file names
// private key and tlsCrt may also be set in the config 'priv' and 'cert' fields.
//
// Because it is not possible to get back the tlsCrt bytes from tlsCrt, return it as well.
func loadCertFromDir(dir string) (*tls.Certificate, []byte, error) {
	keyFile := filepath.Join(dir, tlsKey)
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	certBytes, err := ioutil.ReadFile(filepath.Join(dir, tlsCrt))
	if err != nil {
		return nil, nil, err
	}

	tlsCert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, nil, err
	}

	if tlsCert.Certificate == nil || len(tlsCert.Certificate) == 0 {
		return nil, nil, errors.New("missing certificate")
	}

	return &tlsCert, certBytes, nil
}

//func (a *Mesh) waitAndInitFromDir() error {
//	if a.CertDir == "" {
//		a.CertDir = "./var/run/secrets/istio.io/"
//	}
//	keyFile := filepath.Join(a.CertDir, "key.pem")
//	err := waitFile(keyFile, 5*time.Second)
//	if err != nil {
//		return err
//	}
//
//	err = a.initFromDir()
//	if err != nil {
//		return err
//	}
//
//	return nil
//}

// Same with initFromDir, but will repeat.
func (mesh *Mesh) initFromDirPeriodic(certDir string, first bool) error {
	err := mesh.initFromDir(certDir)
	if err != nil {
		log.Println("certRefresh", err)
		if first {
			return err
		}
	}
	time.AfterFunc(30*time.Minute, func() {
		mesh.initFromDirPeriodic(certDir, false)
	})
	return nil
}

// initFromDir will Init the certificate and roots from a directory
func (mesh *Mesh) initFromDir(certDir string) error {
	_, err := mesh.GetCertificate(context.Background(), "")
	if err != nil {
		return err
	}

	rootCert, _ := ioutil.ReadFile(filepath.Join(certDir, "root-cert.pem"))
	if rootCert != nil {
		err2 := mesh.AddRoots(rootCert)
		if err2 != nil {
			return err2
		}
	}

	istioCert, _ := ioutil.ReadFile("./var/run/secrets/istio/root-cert.pem")
	if istioCert != nil {
		err2 := mesh.AddRoots(istioCert)
		if err2 != nil {
			return err2
		}
	}
	istioCert, _ = ioutil.ReadFile("/var/run/secrets/istio/root-cert.pem")
	if istioCert != nil {
		err2 := mesh.AddRoots(istioCert)
		if err2 != nil {
			return err2
		}
	}

	// Similar with /etc/ssl/certs/ca-certificates.crt - the concatenated list of PEM certs.
	rootCertExtra, _ := ioutil.ReadFile(filepath.Join(certDir, caCrt))
	if rootCertExtra != nil {
		err2 := mesh.AddRoots(rootCertExtra)
		if err2 != nil {
			return err2
		}
	}

	// If the certificate has a chain, use the last cert - similar with Istio
	if mesh.Cert != nil && len(mesh.Cert.Certificate) > 1 {
		last := mesh.Cert.Certificate[len(mesh.Cert.Certificate)-1]

		mesh.AddRootDER(last)
	}

	if mesh.Cert != nil {
		mesh.initFromCert()
	}
	return nil
}

var MarshalPublicKey = certs.MarshalPublicKey

var MarshalPrivateKey = certs.MarshalPrivateKey

// SaveCerts will create certificate files as expected by gRPC and Istio, similar with the
// auto-created files.
//
// This creates 3 files.
// NGinx and others also support one file, in the order cert, intermediary, key,
// and using hostname as the name.
func (mesh *Mesh) SaveCerts(outDir string) error {
	if outDir == "" {
		outDir = varRunSecretsWorkloadSpiffeCredentials
	}
	err := os.MkdirAll(outDir, 0755)
	// TODO: merge other roots as needed - this is Istio XDS server root.
	rootFile := filepath.Join(outDir, caCrt)
	if err != nil {
		return err
	}

	rootsB := bytes.Buffer{}
	for _, k := range mesh.RootCertificates {
		pemb := pem.EncodeToMemory(&pem.Block{Type: blockTypeCertificate, Bytes: k})
		rootsB.Write(pemb)
		rootsB.Write([]byte{'\n'})
	}

	err = ioutil.WriteFile(rootFile, rootsB.Bytes(), 0644)
	if err != nil {
		return err
	}

	keyFile := filepath.Join(outDir, tlsKey)
	chainFile := filepath.Join(outDir, tlsCrt)
	os.MkdirAll(outDir, 0755)

	p := MarshalPrivateKey(mesh.Cert.PrivateKey)

	// TODO: full chain
	bb := bytes.Buffer{}
	for _, crt := range mesh.Cert.Certificate {
		b := pem.EncodeToMemory(
			&pem.Block{
				Type:  blockTypeCertificate,
				Bytes: crt,
			},
		)
		bb.Write(b)
	}

	err = os.WriteFile(keyFile, p, 0666)
	if err != nil {
		return err
	}
	err = os.WriteFile(chainFile, bb.Bytes(), 0666)
	if err != nil {
		return err
	}
	//if os.Getuid() == 0 {
	//	os.Chown(outDir, 1337, 1337)
	//	os.Chown(keyFile, 1337, 1337)
	//	os.Chown(chainFile, 1337, 1337)
	//}

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
// - Use WORKLOAD_CERT json to Init the config for the CSR, create a CSR
// - Call CSRSigner.
// - Save the certificates if running as root or an output dir is set. This will use CAS naming convention.
//
// If envoy + pilot-agent are used, they should be configured to use the cert files.
// This is done by setting "CA_PROVIDER=GoogleGkeWorkloadCertificate" when starting pilot-agent
func (mesh *Mesh) InitCertificates(ctx context.Context, certDir string) error {
	if certDir == "" {
		certDir = varRunSecretsWorkloadSpiffeCredentials
	}
	var err error
	keyFile := filepath.Join(certDir, tlsKey)
	chainFile := filepath.Join(certDir, tlsCrt)
	privPEM, err := os.ReadFile(keyFile)
	certPEM, err := os.ReadFile(chainFile)

	kp, err := tls.X509KeyPair(certPEM, privPEM)
	if err == nil && len(kp.Certificate) > 0 {
		kp.Leaf, _ = x509.ParseCertificate(kp.Certificate[0])

		exp := kp.Leaf.NotAfter.Sub(time.Now())
		if exp > -5*time.Minute {
			mesh.Cert = &kp
			log.Println("Existing Cert", "expires", exp)
			return nil
		}
	}
	return nil
}

// Extract the trustDomain, namespace and Name from a spiffee certificate
func (mesh *Mesh) Spiffee() (*url.URL, string, string, string) {
	cert, err := x509.ParseCertificate(mesh.Cert.Certificate[0])
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

func (mesh *Mesh) WorkloadID() string {
	su, _, _, _ := mesh.Spiffee()
	return su.String()
}

// String returns a json representation of mesh auth.
func (mesh *Mesh) String() string {
	if mesh.Cert == nil || len(mesh.Cert.Certificate) == 0 {
		return "{}"
	}
	cert, err := x509.ParseCertificate(mesh.Cert.Certificate[0])
	if err != nil {
		return ""
	}
	id := ""
	if len(cert.URIs) > 0 {
		id = cert.URIs[0].String()
	}
	return fmt.Sprintf(`{"id":"%s"","iss":"%s","exp":"%v","org":"%s"}`, id, cert.Issuer,
		cert.NotAfter, cert.Subject.Organization)
}

// Add a list of certificates in DER format to the root.
// The top signer of the workload certificate is added by default.
func (mesh *Mesh) AddRootDER(root []byte) error {
	rootCAs, err := x509.ParseCertificates(root)
	mesh.RootCertificates = append(mesh.RootCertificates, root)
	if err == nil {
		for _, c := range rootCAs {
			mesh.trustedCertPool.AddCert(c)
			mesh.meshCertPool.AddCert(c)
		}
	}
	return err
}

// AddRoots will process a PEM file containing multiple concatenated certificates.
func (mesh *Mesh) AddRoots(rootCertPEM []byte) error {
	block, rest := pem.Decode(rootCertPEM)
	//var blockBytes []byte
	for block != nil {
		mesh.AddRootDER(block.Bytes)
		block, rest = pem.Decode(rest)
	}
	return nil
}

// GenerateTLSConfigDest returns a custom tls config for a Dest and a context holder.
// This should be used with a single
func (mesh *Mesh) TLSClient(ctx context.Context, nc net.Conn,
	dest *Dest,
	remotePub32 string) (*tls.Conn, error) {
	tlsc := tls.Client(nc, mesh.TLSClientConf(dest, "", remotePub32))

	if err := tlsc.HandshakeContext(ctx); err != nil {
		// if the context was canceled, return the context error
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}

	return tlsc, nil
}

// HttpClient returns a http.Client configured based on the security settings for Dest.
func (mesh *Mesh) HttpClient(dest *Dest) *http.Client {

	c := dest.HttpClient()

	return c
}

// TLSClientConf returns a config for a specific cluster.
//
// sni can override the cluster sni
// remotePub32 is the cert-baseed identity of a specific endpoint.
func (mesh *Mesh) TLSClientConf(dest *Dest, sni string,
	 remotePub32 string) *tls.Config {

	pool := mesh.meshCertPool //  a.trustedCertPool
	if dest.CACertPEM != nil {
		pool = dest.CertPool()
	}
	if sni == "" {
		sni = dest.SNI
	}
	// We need to check the peer WorkloadID in the VerifyPeerCertificate callback.
	// The tls.Config it is also used for listening, and we might also have concurrent dials.
	// Clone it so we can check for the specific peer WorkloadID we're dialing here.
	conf := &tls.Config{
		// This is not insecure here. We will verify the remote pub in VerifyPeerCertificate.
		InsecureSkipVerify: dest.InsecureSkipTLSVerify, // || remotePub32 != "" ||
			//len(dest.URLSANs) > 0 ||
			//len(dest.DNSSANs) > 0,

		// If dest specifies a pool - use it.
		// Else use the mesh pool
		RootCAs: pool,

		// provide the workload cert if asked
		Certificates:           []tls.Certificate{*mesh.Cert},
		NextProtos:             dest.ALPN,
		ServerName:             sni,
		SessionTicketsDisabled: false,
		ClientSessionCache:     mesh.ClientSessionCache,

		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return mesh.GetCertificate(cri.Context(), "")
		},
	}

	if len(dest.URLSANs) > 0 || len(dest.DNSSANs) > 0  || remotePub32 != ""{
		conf.InsecureSkipVerify = true
		conf.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return mesh.verifyServerCert(dest, sni, rawCerts, verifiedChains, pool,
				remotePub32)
		}
	}
	return conf
}

/*
Cert verification and key ID notes

`openssl x509 -in file.pem -text ` shows among other things

keyid:0F:8B:D4:4D:39:BD:77:D6:1D:6B:C9:CD:C8:AC:CF:0A:14:CB:3F:0C

as the key that signed a particular cert.



*/

// Verify the server certificate. The client TLS context is called with InsecureSkipVerify,
// so 'normal' verification is disabled - only rawCerts are available.
//
// Will check:
// - certificate is valid
// - if it has a Spiffee identity - verify it is in same namespace or istio-system
// - else: verify it matches SNI (unless sni is empty). For DNS only will use provided pool or root certs
func (mesh *Mesh) verifyServerCert(dest *Dest, sni string, rawCerts [][]byte, checked [][]*x509.Certificate, pool *x509.CertPool, remotePub32 string) error {

	if len(checked) != 0 {
		return nil
	}

	if len(rawCerts) == 0 {
		return errors.New("server certificate required")
	}

	// Self-signed certificates need to be verified
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

	// Explicit public key
	if remotePub32 != "" {
		chain, err := RawToCertChain(rawCerts)
		if err != nil {
			return err
		}
		pubKey, err := VerifySelfSigned(chain)
		pubKeyPeerID := PublicKeyBase32SHA(pubKey)
		if err != nil {
			return err
		}

		// TODO: also verify the SAN (Istio and DNS style)

		if remotePub32 != pubKeyPeerID {
			return errors.New("peer IDs don't match")
		} else {
			return nil // all good, verified by known public key
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

		// TODO: check aliases
		if trustDomain != mesh.Domain {

			log.Println("MTLS: invalid trust domain", trustDomain, "self", mesh.Domain, peerCert.URIs)
			return errors.New("invalid trust domain " + trustDomain + " " + mesh.Domain)
		}

		if pool == nil {
			pool = mesh.trustedCertPool
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
		if ns == "istio-system" || ns == mesh.Namespace {
			return nil
		}

		// TODO: check the overrides

		return nil
	} else {
		// TODO: special mesh domain and SNI handling (base32 pub naming)

		// No DomainName since we verified spiffee
		if pool == nil {
			_, err := peerCert.Verify(x509.VerifyOptions{
				Roots:         nil, // use system
				Intermediates: intCertPool,
			})
			if err != nil {
				_, err = peerCert.Verify(x509.VerifyOptions{
					Roots:         mesh.trustedCertPool,
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
		// TODO: slef-signed mesh names
		if strings.HasPrefix(sni, ".mesh") {
			sniparts := strings.Split(sni, ".")
			id := sniparts[0]
			pubKey := peerCert.PublicKey
			//pubKeyPeerID := auth.IDFromCert(chain)
			pubKeyPeerID := PublicKeyBase32SHA(pubKey)
			// TODO: also verify the SAN (Istio and DNS style)

			if id != pubKeyPeerID {
				return errors.New("peer IDs don't match")
			}
		}

		for _, n := range peerCert.DNSNames {
			if n == sni {
				return nil
			}
			for _, n1 := range dest.DNSSANs {
				if n1 == n {
					return nil
				}
			}
		}
		for _, n := range peerCert.IPAddresses {
			if n.String() == sni {
				return nil
			}
		}
		// DNS certificate - need to verify the name separatedly.
		return errors.New("dns cert not found " + sni)
	}
}

func (mesh *Mesh) verifyClientCert(allowMeshExternal bool, rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		if allowMeshExternal {
			return nil
		}
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
		if allowMeshExternal {
			return nil
		}
		log.Println("MTLS: missing URIs in Istio cert", peerCert)
		return errors.New("peer certificate does not contain URI type SAN")
	}
	c0 := peerCert.URIs[0]
	trustDomain := c0.Host
	if trustDomain != mesh.Domain {
		log.Println("MTLS: invalid trust domain", trustDomain, peerCert.URIs)
		return errors.New("invalid trust domain " + trustDomain + " " + mesh.Domain)
	}

	_, err := peerCert.Verify(x509.VerifyOptions{
		Roots:         mesh.trustedCertPool,
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
	if ns == "istio-system" || ns == mesh.Namespace {
		return nil
	}

	// TODO: also validate namespace is same with this workload or in list of namespaces ?
	if len(mesh.AllowedNamespaces) == 0 {
		log.Println("MTLS: namespace not allowed", peerCert.URIs)
		return errors.New("Namespace not allowed")
	}

	if mesh.AllowedNamespaces[0] == "*" {
		return nil
	}

	for _, ans := range mesh.AllowedNamespaces {
		if ns == ans {
			return nil
		}
	}

	log.Println("MTLS: namespace not allowed", peerCert.URIs)
	return errors.New("Namespace not allowed")
}

// GenerateTLSConfigServer is used to provide the server tls.Config for handshakes.
//
// Will use the workload identity and do basic checks on client certs.
// It does not require client certs - but asks for them, and if found verifies.
//
// If allowMeshExternal is set, will skip verification for certs with different
// trust domain.
func (mesh *Mesh) GenerateTLSConfigServer(allowMeshExternal bool) *tls.Config {
	// TODO: setting to allow use of public CAs for server checking clients
	return &tls.Config{
		//MinVersion: tls.VersionTLS13,
		//PreferServerCipherSuites: ugate.preferServerCipherSuites(),
		InsecureSkipVerify: true,                  // This is not insecure here. We will verify the cert chain ourselves.
		ClientAuth:         tls.RequestClientCert, // not require - we'll fallback to JWT
		ClientCAs:          mesh.meshCertPool,
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
			return mesh.GetCertificate(ch.Context(), ch.ServerName)
		},

		// Will check the peer certificate, using the trust roots.
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return mesh.verifyClientCert(allowMeshExternal, rawCerts, verifiedChains)
		},

		NextProtos: []string{"istio", "h2"},
	}
}

// Generate and save the primary self-signed Certificate
func (mesh *Mesh) generateSelfSigned(prefix string, priv crypto.PrivateKey, sans ...string) (tls.Certificate, []byte, []byte) {
	c := &certs.Cert{
		Org: mesh.Domain,
	}
	return c.SignCert(priv, priv, sans...)
}

func (mesh *Mesh) NodeID() []byte {
	return mesh.VIP6[8:]
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
func (mesh *Mesh) Self() string {
	return mesh.VIP6.String()
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

func (mesh *Mesh) NodeIDUInt(pub []byte) uint64 {
	return Pub2ID(pub)
}

// OIDC discovery on .well-known/openid-configuration
func (mesh *Mesh) HandleDisc(w http.ResponseWriter, r *http.Request) {
	// Issuer must match the hostname used to connect.
	//
	w.Header().Set("content-type", "application/json")

	base := "https://" + r.Host
	if r.TLS == nil {
		base = "http://" + r.Host
	}

	fmt.Fprintf(w, `{
  "issuer": "%s",
  "jwks_uri": "%s/.well-known/jwks",
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "ES256"
  ]
}`, base, base)

	// ,"EdDSA"
	// TODO: switch to EdDSA
}


const (
	blockTypeECPrivateKey      = "EC PRIVATE KEY"
	blockTypeRSAPrivateKey   = "RSA PRIVATE KEY" // PKCS#1 private key
	blockTypePKCS8PrivateKey = "PRIVATE KEY"     // PKCS#8 plain private key
	blockTypeCertificate     = "CERTIFICATE"
)

var PublicKey = certs.PublicKey


// Get all known certificates from local files. This is used to support
// lego certificates and istio.
//
// "istio" is a special name, set if istio certs are found
func (mesh *Mesh) GetCerts() map[string]*tls.Certificate {
	certMap := map[string]*tls.Certificate{}

	if _, err := os.Stat("./etc/certs/key.pem"); !os.IsNotExist(err) {
		crt, err := tls.LoadX509KeyPair("./etc/certs/cert-chain.pem", "./etc/certs/key.pem")
		if err != nil {
			log.Println("Failed to Init system istio certs", err)
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
					log.Println("ACME: Failed to Init ", s, err)
				} else {
					certMap[s] = &cert
					log.Println("ACME: Loaded cert for ", s)
				}
			}
		}
	}

	return certMap
}

var GetSAN=certs.GetSAN

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

var VerifySelfSigned = certs.VerifyChain
