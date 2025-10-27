package certs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"strings"
)

// Trust configures the verification (authentication) of the peers.
//
// This can be used for mesh (using namespaces and 'trust domain') or for
// client overrides (custom SNI, ALPN - and trust servers with specific SANs
// or hash of public keys).
//
// It does include small elements of authorization:
// - deny if the peer is not part of the mesh
// - allow only specific namespaces or domains (for Spiffe or DNS)
//
// It can represent the 'default mesh' root of trust or per-domain
// verification.
//
// This is similar to JWT verification: a set of signing keys and restrictions
// on what claims can be set.
type Trust struct {

	Domain              string
	Namespace           string

	RootsPEM string `json:"roots,omitempty"`

	// List of base32(public_key) to be trusted.
	RootPub32 []string

	AllowedNamespaces []string

	// If set to true, allow connections from clients not signed by the
	// trusted roots, and allow connections to servers not signed by trusted
	// roots or root CAs.
	//
	// The certificate public key will be verified out-of-band, using TOFU or
	// DNS or other mechanisms.
	AllowMeshExternal bool

	// Trusted roots - used for verification. RawSubject is used as key - Subjects() return the DER list.
	// This is 'write only', used as a cache in verification.
	//
	// TODO: copy Istiod multiple trust domains code. This will be a map[trustDomain]roots and a
	// list of TrustDomains. XDS will return the info via ProxyConfig.
	// This can also be done by krun - loading a config map with same info.
	certPool          *x509.CertPool

	// If empty, the cluster is using system certs or SPIFFE CAs - as configured in
	// Mesh.
	//
	// Otherwise, it's the configured root certs list, in PEM format.
	// May include multiple concatenated roots.
	//
	// TODO: allow root SHA only.
	// TODO: move to trust config
	CACertPEM string`json:"ca_cert,omitempty"`


	// Expected SANs - if not set, the DNS host in the address is used.
	// For mesh FQDNs, the namespace will be checked ( second part of the FQDN )
	DNSSANs []string `json:"dns_san,omitempty"`
	//IPSANs  []string `json:"ip_san,omitempty"`
	URLSANs []string `json:"url_san,omitempty"`
	// SNI to use when making the request. Defaults to hostname in Addr
	SNI string `json:"sni,omitempty"`

	ALPN []string `json:"alpn,omitempty"`

	// Associated with a trust, used by clients.
	ClientSessionCache tls.ClientSessionCache `json:"-"`
}


// MeshTrust configures mesh-style trust, where all identities signed by
// a set of CAs are trusted.
//
// Trust allow per-identity configuration, and is loaded on-demand from
// the config store (or DNS)
type MeshTrust struct {

	// Used by mesh clients, for tickets.
	ClientSessionCache tls.ClientSessionCache `json:"-"`

	RootsPEM string `json:"roots,omitempty"`

	// This is the 'trust domain' for Istio-style certs, also
	// can be used with SERVICE.NAMESPACE.svc.DOMAIN or POD.NAMESPACE.DOMAIN
	//
	// If not set, '.local' and '.internal' are used.
	Domain []string `json:"domain"`

	// If set, limits the namespaces that are allowed to connect.
	// Same namespace and 'istio-system' are allowed by default.
	//
	// If set, no external certificates are allowed for clients.
	// Public certs for servers continue to be allowed (block internet
	// egress using network rules, not cert rules).
	AllowedNamespaces []string

	certPool *x509.CertPool

	// AllowMeshExternal indicates that client certificates not signed by
	// a certPool certificare - but valid - will be allowed. The server
	// can inspect the cert chain in the connection and make
	// decisions based on the signers.
	AllowMeshExternal bool `json:"-"`
}

func NewTrust() *Trust {
	return &Trust{
		// By default use a small cache for tickets. Will be keyed by SNI or address.
		// When connecting end to end to a service SNI, the workloads should NOT send
		// tickets - since each will have a different key.
		// Only if a sync key is used should they be allowed - but that should be
		// controlled server side, since we can't control the clients to not attempt.
		ClientSessionCache: tls.NewLRUClientSessionCache(64),
	}
}

// CertPool returns the list of roots to be trusted for this dest.
// Also implements caddy CA interface for trust anchors.
//
// TODO: move this to certs package and use a reference, also handle DNS
func (d *Trust) CertPool() *x509.CertPool {
	if d.certPool == nil {
		d.Provision(context.Background())
	}
	return d.certPool
}


func (t *Trust) Provision(ctx context.Context) error {
	if t.AllowMeshExternal {
		sp, _ := x509.SystemCertPool()
		t.certPool = sp.Clone()
	} else {
		t.certPool = x509.NewCertPool()
	}

	addRoots(t.certPool, t.CACertPEM)
	return nil
}

// addRoots will process a PEM file containing multiple concatenated certificates.
func addRoots(pool *x509.CertPool, rootCertPEM string) error {
	// lazy, using sha256.Sum224 as key in a map
	pool.AppendCertsFromPEM([]byte(rootCertPEM))
	//block, rest := pem.Decode([]byte(rootCertPEM))
	//for block != nil {
	//	rootCAs, err := x509.ParseCertificates(block.Bytes)
	//	if err != nil {
	//		return err
	//	}
	//	for _, c := range rootCAs {
	//		pool.AddCert(c)
	//	}
	//	block, rest = pem.Decode(rest)
	//}
	return nil
}

//func (mesh *Trust) RootsPEM() string {
//	rootsB := bytes.Buffer{}
//	for _, k := range mesh.RootCertificatesDER {
//		pemb := pem.EncodeToMemory(&pem.Block{Type: BlockTypeCertificate, Bytes: k})
//		rootsB.Write(pemb)
//		rootsB.Write([]byte{'\n'})
//	}
//	return string(rootsB.Bytes())
//}


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
func (dest *Trust) verifyServerCert(sni string, rawCerts [][]byte, checked [][]*x509.Certificate, pool *x509.CertPool, remotePub32 string) error {

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
		pubKey, err := VerifyChain(chain)
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
		if trustDomain != dest.Domain {

			log.Println("MTLS: invalid trust domain", trustDomain, "self", dest.Domain, peerCert.URIs)
			return errors.New("invalid trust domain " + trustDomain + " " + dest.Domain)
		}

		if pool == nil {
			pool = dest.certPool
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
		if ns == "istio-system" || ns == dest.Namespace {
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
					Roots:         dest.certPool,
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


func NewMeshTrust() *MeshTrust {
	return &MeshTrust{
		// By default use a small cache for tickets. Will be keyed by SNI or address.
		// When connecting end to end to a service SNI, the workloads should NOT send
		// tickets - since each will have a different key.
		// Only if a sync key is used should they be allowed - but that should be
		// controlled server side, since we can't control the clients to not attempt.
		ClientSessionCache: tls.NewLRUClientSessionCache(64),
		certPool:           x509.NewCertPool(),
	}
}

func (t *MeshTrust) Provision(ctx context.Context) error {
	addRoots(t.certPool,t.RootsPEM)
	return nil
}

// AddRoots will process a PEM file containing multiple concatenated certificates.
func (mesh *MeshTrust) AddRoots(rootCertPEM []byte) error {
	block, rest := pem.Decode(rootCertPEM)
	//var blockBytes []byte
	for block != nil {
		mesh.AddRootDER(block.Bytes)
		block, rest = pem.Decode(rest)
	}
	return nil
}

// Add a list of certificates in DER format to the root.
// The top signer of the workload certificate is added by default.
func (mesh *MeshTrust) AddRootDER(root []byte) error {
	rootCAs, err := x509.ParseCertificates(root)
	//mesh.RootCertificates = append(mesh.RootCertificates, root)
	if err == nil {
		for _, c := range rootCAs {
			//mesh.trustedCertPool.AddCert(c)
			mesh.certPool.AddCert(c)
		}
	}
	return err
}


// VerifyClientCert is specific to servers accepting connections.
// Only used if 'request certificat' is set in the tls.Config, and
// if a certificate is provided by client.
func (mesh *MeshTrust) VerifyClientCert(allowMeshExternal bool, rawCerts [][]byte, _ [][]*x509.Certificate) error {
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

	// TODO: allow DNS certs with *.NAMESPACE.DOMAIN first
	// Also email-NAMESPACE@DOMAIN

	if peerCert == nil || len(peerCert.URIs) == 0 {
		if allowMeshExternal {
			return nil
		}
		log.Println("MTLS: missing URIs in Istio cert", peerCert)
		return errors.New("peer certificate does not contain URI type SAN")
	}

	c0 := peerCert.URIs[0]
	trustDomain := c0.Host

	found := false
	for _, dn := range mesh.Domain {
		if trustDomain == dn {
			found = true
			break
		}
	}

	if !found {
		log.Println("MTLS: invalid trust domain", trustDomain, peerCert.URIs)
		return errors.New("invalid trust domain " + trustDomain)
	}

	_, err := peerCert.Verify(x509.VerifyOptions{
		Roots:         mesh.certPool,
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
	if ns == "istio-system" {
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
