package meshauth

import (
	"crypto/x509"
	"errors"
	"net/http"
)

// Dest represents a destination and associated security info.
//
// In Istio this is represented as DestinationRule, Envoy - Cluster.
//
// This is primarily concerned with the security aspects (auth, transport),
// and include 'trusted' attributes from K8S configs or JWT/cert.
type Dest struct {
	// Client certificates to use in the request, represented as a MeshAuth object.
	MeshAuth *MeshAuth

	// BaseAddr is the URL, including any required path prefix, for the destination.
	BaseAddr string

	// If set, should be used when connecting to the dest
	SNI string

	// If empty, the cluster is using system certs or SPIFFE
	// Otherwise, it's the configured root certs list, in PEM format.
	// May include multiple concatenated roots.
	CACertPEM []byte

	// If set, this is required to verify the certs of dest if https is used
	// If not set, system certs are used
	RootCA *x509.CertPool

	// If set, the token source will be used.
	// Using gRPC interface which returns the full auth string, not only the token
	//
	TokenSource PerRPCCredentials

	// WebpushPublicKey is the client's public key. From the getKey("p256dh") or keys.p256dh field.
	// This is used for Dest that accepts messages encrypted using webpush spec, and may
	// be used for validating self-signed destinations - this is expected to be the public
	// key of the destination.
	WebpushPublicKey []byte

	// WebpushAuth is a value used by the client to validate the encryption. From the
	// keys.auth field.
	// The encrypted aes128gcm will have 16 bytes authentication tag derived from this.
	// This is the pre-shared authentication secret. May be used outside of Webpush for destinations
	// using a shared secret.
	WebpushAuth []byte
}

func (d *Dest) GetCACertPEM() []byte {
	return d.CACertPEM
}

func (d *Dest) AddCACertPEM(pems []byte) error {
	if d.RootCA == nil {
		d.RootCA = x509.NewCertPool()
	}
	if d.CACertPEM != nil {
		d.CACertPEM = append(d.CACertPEM, '\n')
		d.CACertPEM = append(d.CACertPEM, pems...)
	} else {
		d.CACertPEM = pems
	}
	if !d.RootCA.AppendCertsFromPEM(pems) {
		return errors.New("Failed to decode PEM")
	}
	return nil
}

// H2Client returns an H2C client configured to communicate with the dest.
func (d *Dest) H2Client() *http.Client {
	// Doesn't require TLS client certsor not configured with a plugin
	if d.MeshAuth == nil || d.MeshAuth.Transport == nil {
		// TODO: implement
		return http.DefaultClient
	}
	hc := &http.Client{
		Transport: d.MeshAuth.Transport(d),
	}

	return hc
}
