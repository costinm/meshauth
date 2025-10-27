package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
)

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


const (
	BlockTypeECPrivateKey    = "EC PRIVATE KEY"
	BlockTypeRSAPrivateKey   = "RSA PRIVATE KEY" // PKCS#1 private key
	BlockTypePKCS8PrivateKey = "PRIVATE KEY"     // PKCS#8 plain private key
	BlockTypeCertificate = "CERTIFICATE"
)

var (
	oidExtensionSubjectAltName = []int{2, 5, 29, 17}
)

const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

// MarshalPrivateKeyPEM returns the PEM encoding of the key
func MarshalPrivateKeyPEM(priv crypto.PrivateKey) []byte {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		encodedKey := x509.MarshalPKCS1PrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: BlockTypeRSAPrivateKey, Bytes: encodedKey})
	case *ecdsa.PrivateKey:
		encodedKey, _ := x509.MarshalECPrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: BlockTypeECPrivateKey, Bytes: encodedKey})
	case ed25519.PrivateKey:
		// TODO: what is the std encoding for ed25529 ?
		return []byte(base64.RawURLEncoding.EncodeToString(k))
	}

	return nil
}


func getSANExtension(c *x509.Certificate) []byte {
	for _, e := range c.Extensions {
		if e.Id.Equal(oidExtensionSubjectAltName) {
			return e.Value
		}
	}
	return nil
}


func GenerateKey(kty string) crypto.PrivateKey {
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

func GetSANRequest(req *http.Request) ([]string, error) {
	tls := req.TLS
	if tls != nil && len(tls.PeerCertificates) > 0 {
		// pk1 := tls.PeerCertificates[0].PublicKey

		// RemoteID = certs.PublicKeyBase32SHA(pk1)
		// TODO: Istio-style, signed by a trusted CA. This is also for SSH-with-cert
		sans, err := GetSAN(tls.PeerCertificates[0])
		return sans, err
	}
	return nil, nil
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

// VerifySelfSigned verifies the certificate chain and extract the remote's public key.
// The last element in the chain is expected to be the root - which should be checked against DANE
// or static config.
func VerifyChain(chain []*x509.Certificate) (crypto.PublicKey, error) {
	if chain == nil || len(chain) == 0 {
		return nil, nil
	}

	leaf := chain[0]

	// Self-signed certificate
	if len(chain) == 1 {
		pool := x509.NewCertPool()
		pool.AddCert(leaf)
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
			// If we return an x509 error here, it will be sent on the wire.
			// Wrap the error to avoid that.
			return nil, fmt.Errorf("certificate verification failed: %s", err)
		}
	} else {
		//
		pool := x509.NewCertPool()
		pool.AddCert(chain[len(chain)-1])
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
			// If we return an x509 error here, it will be sent on the wire.
			// Wrap the error to avoid that.
			return nil, fmt.Errorf("chain certificate verification failed: %s", err)
		}
	}

	// IPFS uses a key embedded in a custom extension, and verifies the public key of the Leaf is signed
	// with the node public key

	// This transport is instead based on standard certs/TLS

	key := leaf.PublicKey
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


// Return the SPKI fingerprint of the key
// https://www.rfc-editor.org/rfc/rfc7469#section-2.4
//
// "An SPKI Fingerprint is defined as the output of a known cryptographic
//   hash algorithm whose input is the DER-encoded ASN.1 representation of
//   the Subject Public Key Info (SPKI) of an X.509 certificate"
// "The SPKI Fingerprint is encoded in base 64 for use in an HTTP header
//   [RFC4648]"
//
// Can be used with "ignore-certificate-errors-spki-list" in chrome, for cert pinning.
//
// User-installed roots can bypass the pins.
//
//	openssl x509 -pubkey -noout -in <path to PEM cert> | openssl pkey -pubin -outform der \
//	  | openssl dgst -sha256 -binary | openssl base32Enc -base64
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

// TLSA records have many types - this is for the Selector=1 (SubjectPublicKeyInfo == public key DER)
// matching=1 (SHA256 - same as in SPKI).
// CertUsage can be 0/2 (root certificate - must be in the chain, doesn't need basicConstraints),
// or 1/3 (Leaf/end certificate). Note that 0,1 require a trustChain root, while 2,3 don't.
//
// Example: _443._tcp.www.example.com. IN TLSA (
//      2 1 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971)
// DNS canonical representation is hex, but the record is binary.
func TLSA(key crypto.PublicKey) string {
	d := MarshalPublicKey(key)
	sum := sha256.Sum256(d)
	pin := make([]byte, 2 * len(sum))
	hex.Encode(pin, sum[:])
	return string(pin)
}


var base32Enc = base32.StdEncoding.WithPadding(base32.NoPadding)


func IDFromPublicKeyBytes(m []byte) string {
	if len(m) > 32 {
		sha256 := sha256.New()
		sha256.Write(m)
		m = sha256.Sum([]byte{}) // 302
	}
	return base32Enc.EncodeToString(m)
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
	return base32Enc.EncodeToString(m)
}

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

