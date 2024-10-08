package tokens

import "strings"

// WIP: Authenticate using Istio mTLS, for gRPC and HTTP
// Not clear it has a future - using JWTs and mapping claims from cert to headers seem more
// consistent and far simpler for users.
// Almost all client certificates have very few useful 'claims'.

// Alternative: https://pkg.go.dev/github.com/alecholmes/xfccparser@v0.1.0

// Envoy generates a header like:
// x-forwarded-client-cert: \
//    By=spiffe://cluster.local/ns/ssh-ca/sa/default;\
//    Hash=881...3da93b;\
//    Subject="";URI=spiffe://cluster.local/ns/sshd/sa/default

// https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
//

//https://httpwg.org/http-extensions/draft-ietf-httpbis-client-cert-field.html
// Client-Cert
// client-cert-chain
// - byte sequence,DER+base64, ::
//

// TLS session resumption doesn't work well with client certs - must be cached in the session data.

// ParseXFCC is a minimal (and probably buggy) parser for XFCC
// envoy header. It does not deal with quoted strings including
// special chars (,;=). Istio certs are safe.
func ParseXFCC(val string) map[string]string {
	// Each element represents a proxy in the path
	// We need the last one
	elems := strings.Split(val, ",")

	last := elems[len(elems)-1]

	m := map[string]string{}
	kvp := strings.Split(last, ";")
	for _, v := range kvp {
		// Note that values may include escaped quotes, and may be quoted if they include , or ;
		// This is not used in istio
		kv := strings.SplitN(v, "=", 2)
		m[kv[0]] = kv[1]
	}
	return m
}
