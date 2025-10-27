package tokens

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"net/http"
)

// OIDC discovery on /.well-known/openid-configuration
func (mesh *Tokens) HandleDisc(w http.ResponseWriter, r *http.Request) {
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


// OIDC JWKS handler
//ca.Mux.HandleFunc("/.well-known/jwks", ca.HandleJWK)
func (a *Tokens) HandleJWK(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(GetJWK(a.Private)))
}

func GetJWK(a crypto.PrivateKey) string {

	pk := a.(*ecdsa.PrivateKey)
	byteLen := (pk.Params().BitSize + 7) / 8
	ret := make([]byte, byteLen)
	pk.X.FillBytes(ret[0:byteLen])
	x64 := base64.RawURLEncoding.EncodeToString(ret[0:byteLen])
	pk.Y.FillBytes(ret[0:byteLen])
	y64 := base64.RawURLEncoding.EncodeToString(ret[0:byteLen])
	return fmt.Sprintf(`{"keys":[{"kty": "EC","crv": "P-256","x": "%s","y": "%s"}]}`, x64, y64)

	//		"crv": "Ed25519",
	//		"kty": "OKP",
	//		"x"   : "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
}
