package meshauth

import (
	"crypto/x509"
	"net/http"
)

// Dest represents a destination and associated security info.
// In Istio this is represented as DestinationRule
type Dest struct {
	// BaseAddr is the URL, including any required path prefix, for the destination.
	BaseAddr string

	// Addr is the IP:port or domainname:port
	//Addr string

	// If set, this SAN should be used when connecting to the dest
	SAN string

	// If set, this is required to verify the certs of dest if https is used
	// If not set, system certs are used
	RootCA *x509.CertPool

	// If set, the token source will be used.
	// Using gRPC interface which returns the full auth strin, not only the token
	TokenSource PerRPCCredentials

	// If set, the workload identity associated with MeshAuth will be used
	// ( typically client certificate), if the server asks.
	MeshAuth *MeshAuth

	Transport func(*Dest) http.RoundTripper

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

// H2Client returns an H2C client configured to communicate with the dest.
func (d *Dest) H2Client() *http.Client {
	if d.Transport == nil {
		return http.DefaultClient
	}
	hc := &http.Client{
		Transport: d.Transport(d),
	}

	return hc
}
