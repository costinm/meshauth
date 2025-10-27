// Package certs provides helpers around certificates.
package certs

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Minimal CA and helper to load, generate and verify X509 certificates.
//
// This package should have no deps outside standard libs.
//
// It is based on some Istio code and concepts, but cleaned up and separated
// from the 'spiffe-only' model.

/*
Cert verification and key ID notes

`openssl x509 -in file.pem -text ` shows among other things

keyid:0F:8B:D4:4D:39:BD:77:D6:1D:6B:C9:CD:C8:AC:CF:0A:14:CB:3F:0C

as the key that signed a particular cert.



*/

// Certs handles certificate and trust management, and is built around a primary
// private key.
//
// It incorporates as private CA that can sign additional certs for
// subdomains, a filesystem for loading secrets, a filesystem for loading
// configs for client connections and an optional directory for local files
// and cache.
type Certs struct {
	// Local dir. If set, private key and certificates are saved there.
	// If not set, they will be loaded from SecretFS (keys), or auto-generated
	// ephemeral key are used.
	BaseDir string `json:"base,omitempty"`

	// Private key for the workload, used for signing.
	// The associated public key should be used to configure trust in this
	// workload and any identities it may use (impersonate) or delegate.
	Private crypto.PrivateKey `json:"-"`

	// CACert is a certificate associated with the private key, with the
	// CA bit set. Used to generate certificates signed by this workload.
	CACert *x509.Certificate `json:"-"`

	// FQDN is the FQDN of the workload.
	//
	// In Istio, the constant 'cluster.local' is
	// used for the mesh CA, which indicates a custom location is
	// used for the root key and use of SPIFFE certificates.
	//
	// Default to 'hostname' or env HOST and DOMAIN
	// The second component is treated as 'namespace'.
	FQDN string `json:"trustDomain,omitempty"`

	// The CA Certificate may be signed by multiple intermediaries
	// They need to be included in chains.
	// May include the top-level root - but this is not required.
	IntermediatesPEM []byte `json:"chainPEM,omitempty"`

	// For self-signed cert ('root'), this is the cert corresponding to
	// the private key. This needs to be added to the trust store.
	// This is NOT included in Intermediates - which are signatures by
	// other CAs that MUST be included in generated chains, so clients
	// can find a path to the other CAs.
	//
	// This is used if this CA is the top-level CA, signing other CAs - and
	// MUST be added to the trust store of each client.
	//
	// Since it is self-signed, the CA can re-generated this file.
	// For the chain, the signing CA (provider) must issue them again.
	CACertPEM []byte `json:"selfPEM,omitempty"`

	LoadTime time.Time `json:"-"`

	// Trust configures private CA roots as 'trusted'.
	// If no CA root is found, default is to trust the internal CA and
	// public roots.
	//
	// Each peer must have a valid certificate. If Trust is defined, the
	// cert must have a signature from one of the defined public keys.
	// This field includes CA-style keys, valid for all identities.
	Trust *MeshTrust `json:"trust"`

	// A filesystem interface for loading private keys. May also include
	// configs and certificates.
	SecretsFS fs.FS

	// A filesystem holding server certificates and configs. Loaded on-demand.
	// If a cert is not found - the internal CA will generate one.
	ConfigFS fs.FS

	// Cert is the workload certificate - should encode the primary FQDN of
	// the node.
	*Cert

	// Private key as a string (base64). EC256 is 33 bytes, ED25519 16 bytes,
	// and RSA encoded as PEM.
	PrivateString string `json:"key"`
}

func NewCerts() *Certs {
	return &Certs{
		Cert: &Cert{},
	}
}

func (certs *Certs) Provision(ctx context.Context) error {

	if certs.Private != "" {

	}
	if certs.BaseDir != "" {
		err := certs.Init(certs.BaseDir)
		if err != nil {
			return err
		}
		// TODO: if Base and filesystem are specified, and the file does not
		// exist - create it.
	}
	if certs.Private == nil {
		certs.newRoot()
	}

	// Attempt to load private key from SecretFS or BaseDir

	// If a key is found, also attempt to load a certificate

	if certs.Cert == nil {
		certs.Cert = certs.InitSelfSigned("", certs.FQDN)
		if certs.Cert == nil {
			return errors.New("certs.InitSelfSigned")
		}

		if certs.BaseDir != "" {
			// We have a local dir, save it. If not set - all is ephemeral.
			err := certs.Save(ctx, certs.BaseDir)
			if err != nil {
				return err
			}
		}

	}

	return nil
}

// GetCertificate is typically called during handshake, both server and client.
// "sni" will be empty for client certificates, and set for server certificates - if not set, workload id is returned.
//
// ctx is the handshake context - may include additional metadata about the operation.
func (certs *Certs) GetCertificate(ctx context.Context, sni string) (*tls.Certificate, error) {
	// TODO: if host != "", allow returning DNS certs for the host.
	// Default (and currently only impl) is to return the spiffe cert
	// May refresh.
	// doesn't include :5228
	// Have cert, not expired
	if sni == "" {
		if certs.Cert != nil {
			if !certs.Cert.Leaf().NotAfter.Before(time.Now()) {

				return certs.Cert.Certificate, nil
			}
		}

		if certs.BaseDir != "" {
			c, _, err := loadCertFromDir(certs.BaseDir)
			if err == nil {
				if certs.Cert == nil || !c.Leaf.NotAfter.Before(time.Now()) {
					certs.Cert.Certificate = c
				}
			}
			return c, nil
		}
		return nil, nil
	}

	// TODO: use the local CA to issue a cert.
	// Caller will need to configure the trust handling and verify that domain
	// is delegated.
	if certs.Cert == nil {
		certs.Cert = certs.InitSelfSigned("", certs.FQDN)
	}

	return certs.Cert.Certificate, nil
}

func (certs *Certs) InitSelfSigned(kty string, fqdn string) *Cert {
	pk := GenerateKey(kty)

	return certs.InitSelfSignedKeyRaw(pk, fqdn)
}

func (certs *Certs) InitSelfSignedKeyRaw(privk crypto.PrivateKey, fqdn string) *Cert {
	tlsCert, _, _ := certs.generateSelfSigned(privk, fqdn)

	cert := NewCert()
	cert.Certificate = &tlsCert
	//mesh.Priv = kty

	return cert
}

// All 'PEM' parameters and return values are string
// All DER are []byte
// Suffix is also used in methods and param names, to avoid confusion
// EC256 and ED also use 'Raw' and 'RawB64' - length can identify the key type

// InitSelfSignedFromPEMKey will use the private key (EC PEM) and generate a self
// signed certificate, using the config (name.domain)
func (certs *Certs) InitSelfSignedFromPEMKey(keyPEM string, fqdn string) *Cert {
	// Use pre-defined private key
	block, _ := pem.Decode([]byte(keyPEM))
	if block != nil {
		if block.Type == "EC PRIVATE KEY" {
			privk, _ := x509.ParseECPrivateKey(block.Bytes)
			return certs.InitSelfSignedKeyRaw(privk, fqdn)
		}
	}

	return nil
}

// Generate and save the primary self-signed Certificate
func (certs *Certs) generateSelfSigned(priv crypto.PrivateKey, sans ...string) (tls.Certificate, []byte, []byte) {
	c := &Cert{}
	return c.SignCert(priv, priv, sans...)
}

// loadCertFromDir will attempt to read from a tlsCrt directory, attempting well-known file names
// private key and tlsCrt may also be set in the config 'priv' and 'cert' fields.
//
// Because it is not possible to get back the tlsCrt bytes from tlsCrt, return it as well.
func loadCertFromDir(dir string) (*tls.Certificate, []byte, error) {
	keyFile := filepath.Join(dir, keyFile)
	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	certBytes, err := ioutil.ReadFile(filepath.Join(dir, chainFile))
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

// Same with initFromDir, but will repeat.
func (certs *Certs) initFromDirPeriodic(certDir string, first bool) error {
	err := certs.initFromDir(certDir)
	if err != nil {
		log.Println("certRefresh", err)
		if first {
			return err
		}
	}
	time.AfterFunc(30*time.Minute, func() {
		certs.initFromDirPeriodic(certDir, false)
	})
	return nil
}

const varRunSecretsWorkloadSpiffeCredentials = "/var/run/secrets/workload-spiffe-credentials"

func (certs *Certs) FromEnv() error {
	certDir := certs.BaseDir
	if certDir == "" {
		// Try to find the 'default' certificate directory
		if _, err := os.Stat(filepath.Join("./", keyFile)); !os.IsNotExist(err) {
			certDir = "./"
		} else if _, err := os.Stat(filepath.Join(varRunSecretsWorkloadSpiffeCredentials, keyFile)); !os.IsNotExist(err) {
			certDir = varRunSecretsWorkloadSpiffeCredentials
		} else if _, err := os.Stat(filepath.Join("/var/run/secrets/istio", "key.pem")); !os.IsNotExist(err) {
			certDir = "/var/run/secrets/istio/"
		} else if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".ssh", keyFile)); !os.IsNotExist(err) {
			certDir = filepath.Join(os.Getenv("HOME"), ".ssh")
		}
	}

	return nil
}

// initFromDir will Init the certificate and roots from a directory.
func (certs *Certs) initFromDir(certDir string) error {

	//_, err := mesh.GetCertificate(context.Background(), "")
	//if err != nil {
	//	return err
	//}

	//rootCert, _ := ioutil.ReadFile(filepath.Join(certDir, "root-cert.pem"))
	//if rootCert != nil {
	//	err2 := mesh.AddRoots(rootCert)
	//	if err2 != nil {
	//		return err2
	//	}
	//}

	//istioCert, _ := ioutil.ReadFile("./var/run/secrets/istio/root-cert.pem")
	//if istioCert != nil {
	//	err2 := mesh.AddRoots(istioCert)
	//	if err2 != nil {
	//		return err2
	//	}
	//}
	//istioCert, _ = ioutil.ReadFile("/var/run/secrets/istio/root-cert.pem")
	//if istioCert != nil {
	//	err2 := mesh.AddRoots(istioCert)
	//	if err2 != nil {
	//		return err2
	//	}
	//}

	// Similar with /etc/ssl/certs/ca-certificates.crt - the concatenated list of PEM certs.

	// ca.crt

	rootCertExtra, _ := ioutil.ReadFile(filepath.Join(certDir, caCrt))
	if rootCertExtra != nil {
		err2 := certs.Trust.AddRoots(rootCertExtra)
		if err2 != nil {
			return err2
		}
	}

	// If the certificate has a chain, use the last cert - similar with Istio
	//if mesh.Cert != nil && len(mesh.Cert.Certificate) > 1 {
	//	last := mesh.Cert.Certificate[len(mesh.Cert.Certificate)-1]
	//
	//	mesh.AddRootDER(last)
	//}

	//if mesh.Cert != nil {
	//	mesh.initFromCert()
	//}
	return nil
}

// Get all known certificates from local files. This is used to support
// lego certificates and istio.
//
// "istio" is a special name, set if istio certs are found
func (certs *Certs) GetCerts() map[string]*tls.Certificate {
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

// WIP
func (certs *Certs) DialTLS(nc net.Conn, addr string) (*tls.Conn, error) {
	// TODO: use addr and ConfigFS to locate a per-addr Trust and
	// overrides. On-demand.
	tlsClientConfig := certs.Cert.TLSClientConf(nil, addr, addr, certs.Trust)

	tlsTun := tls.Client(nc, tlsClientConfig)
	ctx, cf := context.WithTimeout(context.Background(), 3*time.Second)
	defer cf()

	err := tlsTun.HandshakeContext(ctx)

	if err != nil {
		return nil, err
	}
	return tlsTun, nil
}
