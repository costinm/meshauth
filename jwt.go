package meshauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Few minimal helper functions to avoid deps and handle k8s-specific variants.
// Goal is to also compile to WASM - common library is go-jose.
//

// First part of the token.
type JWTHead struct {
	Typ string `json:"typ"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid"`
}

// JWT includes minimal field for a JWT, primarily for extracting iss for the exchange.
//
// This is also used with K8S JWTs, which use multi-string.
type JWT struct {
	//An "aud" (Audience) claim in the token MUST include the Unicode
	//serialization of the origin (Section 6.1 of [RFC6454]) of the push
	//resource URL.  This binds the token to a specific push service and
	//ensures that the token is reusable for all push resource URLs that
	//share the same origin.
	// In K8S it is an array !
	Aud MultiString `json:"aud,omitempty"`

	//If the application server wishes to provide contact details, it MAY
	//include a "sub" (Subject) claim in the JWT.  The "sub" claim SHOULD
	//include a contact URI for the application server as either a
	//"mailto:" (email) [RFC6068] or an "https:" [RFC2818] URI.
	//
	// For K8S, system:serviceaccount:NAMESPACE:KSA
	Sub string `json:"sub,omitempty"`

	// Max 24h
	Exp int64 `json:"exp,omitempty"`
	IAT int64 `json:"iat,omitempty"`

	// Issuer - for example kubernetes/serviceaccount.
	Iss string `json:"iss,omitempty"`

	Email string `json:"email,omitempty"`

	EmailVerified bool `json:"email_verified,omitempty"`

	//  \"kubernetes.io\":{\"namespace\":\"default\",\"serviceaccount\":{\"name\":\"default\",
	// \"uid\":\"a47d63f6-29a4-4e95-94a6-35e39ee6d77c\"}},
	K8S *K8SAccountInfo `json:"kubernetes.io,omitempty"`

	Name string `json:"kubernetes.io/serviceaccount/service-account.name,omitempty"`

	// Raw payload string - for custom claims

	Head    *JWTHead `json:"-"`
	Signed  []byte   `json:"-"`
	Payload []byte   `json:"-"`
	Sig     []byte   `json:"-"`
	Raw     string   `json:"-"`
}

func (j *JWT) Expiry() time.Time {
	return time.Unix(j.Exp, 0)
}

func (j *JWT) KSA() (string, string) {
	if !strings.HasPrefix(j.Sub, "system:serviceaccount") {
		return "", ""
	}

	parts := strings.Split(j.Sub, ":")
	if len(parts) < 4 {
		return "", ""
	}
	return parts[2], parts[3]
}

type K8SAccountInfo struct {
	Namespace string `json:"namespace,omitempty"`
}

type MultiString []string

func (ms *MultiString) MarshalJSON() ([]byte, error) {
	sa := []string(*ms)
	if len(sa) == 0 {
		return []byte{}, nil
	}
	if len(sa) == 1 {
		return json.Marshal(sa[0])
	}
	return json.Marshal(sa)
}

func (ms *MultiString) UnmarshalJSON(data []byte) error {
	if len(data) > 0 {
		switch data[0] {
		case '"':
			var s string
			if err := json.Unmarshal(data, &s); err != nil {
				return err
			}
			*ms = append(*ms, s) // multiString(s)
		case '[':
			var s []string
			if err := json.Unmarshal(data, &s); err != nil {
				return err
			}
			*ms = append(*ms, s...) // multiString(strings.Join(s, ","))
		}
	}
	return nil
}

// TokenPayload returns the decoded token. Used for logging/debugging token content, without printing the signature.
func TokenPayload(jwt string) string {
	jwtSplit := strings.Split(jwt, ".")
	if len(jwtSplit) < 2 {
		return ""
	}
	//Ex: azp,"email","exp":1629832319,"iss":"https://accounts.google.com","sub":"1118295...
	payload := jwtSplit[1]

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}

	return string(payloadBytes)
}

// DecodeJWT decodes the content of a token. No signature checks.
func DecodeJWT(jwt string) *JWT {
	_, j, _, _, _ := JwtRawParse(jwt)
	return j
}

func (jwt *JWT) Sign(privateKey crypto.PrivateKey) string {
	t, _ := json.Marshal(jwt)

	enc := base64.RawURLEncoding
	// Base64URL for the content of the token
	t64 := make([]byte, enc.EncodedLen(len(t)))
	enc.Encode(t64, t)

	token := make([]byte, len(t)+len(vapidPrefix)+100)
	if _, ok := privateKey.(*ecdsa.PrivateKey); ok {
		token = append(token[:0], vapidPrefix...)
	} else if _, ok := privateKey.(ed25519.PrivateKey); ok {
		token = append(token[:0], vapidPrefixED...)
	} else {
		return ""
	}
	token = append(token, t64...)

	hasher := crypto.SHA256.New()
	hasher.Write(token)

	var sig []byte
	if ec, ok := privateKey.(*ecdsa.PrivateKey); ok {
		if r, s, err := ecdsa.Sign(rand.Reader, ec, hasher.Sum(nil)); err == nil {
			// Vapid key is 32 bytes
			keyBytes := 32
			sig = make([]byte, 2*keyBytes)

			rBytes := r.Bytes()
			rBytesPadded := make([]byte, keyBytes)
			copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

			sBytes := s.Bytes()
			sBytesPadded := make([]byte, keyBytes)
			copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

			sig = append(sig[:0], rBytesPadded...)
			sig = append(sig, sBytesPadded...)

		}
	} else if ed, ok := privateKey.(ed25519.PrivateKey); ok {
		sig, _ = ed.Sign(rand.Reader, hasher.Sum(nil), nil)
	}
	sigB64 := make([]byte, enc.EncodedLen(len(sig)))
	enc.Encode(sigB64, sig)

	token = append(token, dot...)
	token = append(token, sigB64...)

	return string(token)
}

func (j *JWT) VerifySignature(pk crypto.PublicKey) error {
	_, err := JWTVerifySignature(j.Head, j, j.Signed, j.Sig, pk)
	return err
}

// JWTVerifySignature will verify "txt" using a public key or other verifiers.
func JWTVerifySignature(h *JWTHead, b *JWT, txt []byte, sig []byte, pk crypto.PublicKey) (*JWT, error) {
	hasher := crypto.SHA256.New()
	hasher.Write(txt)

	if h.Alg == "ES256" {
		r := big.NewInt(0).SetBytes(sig[0:32])
		s := big.NewInt(0).SetBytes(sig[32:64])
		match := ecdsa.Verify(pk.(*ecdsa.PublicKey), hasher.Sum(nil), r, s)
		if !match {
			return nil, errors.New("invalid ES256 signature")
		}
		return b, nil
	} else if h.Alg == "EdDSA" {
		ok := ed25519.Verify(pk.(ed25519.PublicKey), hasher.Sum(nil), sig)
		if !ok {
			return nil, errors.New("invalid ED25519 signature")
		}

	} else if h.Alg == "RS256" {
		rsak := pk.(*rsa.PublicKey)
		hashed := hasher.Sum(nil)
		err := rsa.VerifyPKCS1v15(rsak, crypto.SHA256, hashed, sig)
		if err != nil {
			return nil, err
		}
		return b, nil
	}

	return nil, errors.New("Unsupported " + h.Alg)
}

// JwtRawParse will parse the JWT and extract the elements.
// WILL NOT VERIFY.
// From go-oidc/verify.go
func JwtRawParse(tok string) (head *JWTHead, jwt *JWT, payload []byte, sig []byte, err error) {
	// Token is parsed with square/go-jose
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return nil, nil, nil, nil, fmt.Errorf("malformed jwt, parts=%d", len(parts))
	}

	headRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("malformed jwt[0] %v %s", err, parts[0])
		//log.Println("malformed jwt[0]", err, parts[0], string(headRaw))
	}

	h := &JWTHead{}
	err = json.Unmarshal(headRaw, h)
	if err != nil {
		//log.Println("malformed json jwt[0]", err, string(headRaw))
		return nil, nil, nil, nil, fmt.Errorf("malformed json on jwt[0] %v %s", err, parts[0])
	}

	payload, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("malformed jwt[1] %v %s", err, parts[1])
	}
	b := &JWT{}
	err = json.Unmarshal(payload, b)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("malformed json jwt[1] %v %s", err, parts[1])
	}

	b.Raw = tok
	b.Payload = payload
	b.Signed = []byte(tok[0 : len(parts[0])+len(parts[1])+1])
	b.Head = h
	if len(parts) > 2 {
		sig, _ = base64.RawURLEncoding.DecodeString(parts[2])
		// Allow invalid / missing signature - verify will check if needed
		// In some cases the gateway will wipe the sig.
		b.Sig = sig
	}
	return h, b, []byte(tok[0 : len(parts[0])+len(parts[1])+1]), sig, nil
}

// checkAudience() returns true if the audiences to check are in
// the expected audiences. Otherwise, return false.
func (j *JWT) CheckAudience(audExpected []string) bool {
	for _, a := range j.Aud {
		for _, b := range audExpected {
			if a == b {
				return true
			}
		}
	}
	return false
}

func (j *JWT) K8SInfo() (string, string) {
	if strings.HasPrefix(j.Sub, "system:serviceaccount:") {
		parts := strings.Split(j.Sub, ":")
		return parts[2], parts[3]
	}
	return "", ""
}

func (j *JWT) Audience() string {
	if j.Aud == nil || len(j.Aud) == 0 {
		return ""
	}
	return j.Aud[0]
}

func (j *JWT) String() string {
	b, err := json.Marshal(j)
	if err != nil {
		return err.Error()
	}
	return string(b)
}
