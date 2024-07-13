package meshauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
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
	Typ string `json:"typ,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid   string          `json:"kid,omitempty"`
	JWK   json.RawMessage `json:"jwk,omitempty"`
	Nonce string          `json:"nonce,omitempty"`
	URL   string          `json:"url,omitempty"`
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
	// Also includes kubernetes.io/serviceaccount/namespace, etc - more verbose and not std
	Sub string `json:"sub,omitempty"`

	// Max 24h
	Exp int64 `json:"exp,omitempty"`
	IAT int64 `json:"iat,omitempty"`

	// Issuer - usually a URL, with OIDC keys.
	// Legacy K8S: kubernetes/serviceaccount
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

// JWS is the full form, used in ACME protocol with the full header.
type JWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Sig       string `json:"signature"`
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
	jwt = strings.TrimPrefix(jwt, "Bearer ")
	jwt = strings.TrimPrefix(jwt, "bearer ")
	_, j, _, _, _ := JwtRawParse(jwt)
	return j
}

// Sign will sign the json body and return a JWT token.
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

	sig := Sign(token, privateKey)

	sigB64 := make([]byte, enc.EncodedLen(len(sig)))
	enc.Encode(sigB64, sig)

	token = append(token, dot...)
	token = append(token, sigB64...)

	return string(token)
}


var (
	// encoded {"typ":"JWT","alg":"ES256"}
	vapidPrefix = []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.")
	// encoded {"typ":"JWT","alg":"EdDSA"}
	//https://tools.ietf.org/html/rfc8037
	vapidPrefixED = []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.")
	dot           = []byte(".")
)


func (j *JWT) VerifySignature(pk crypto.PublicKey) error {
	_, err := JWTVerifySignature(j.Head, j, j.Signed, j.Sig, pk)
	return err
}

// JWTVerifySignature will verify "txt" using a public key or other verifiers.
func JWTVerifySignature(h *JWTHead, b *JWT, txt []byte, sig []byte, pk crypto.PublicKey) (*JWT, error) {
	err := VerifyKey(h.Alg, txt, pk, sig)
	if err != nil {
		return nil, err
	}


	return b, nil
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


// Code extracted from x/crypto/acme - exported and made general purpose.

// jwsHasher indicates suitable JWS algorithm name and a hash function
// to use for signing a digest with the provided key.
// It returns ("", 0) if the key is not supported.
func jwsHasher(pub crypto.PublicKey) (string, crypto.Hash) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return "RS256", crypto.SHA256
	case *ecdsa.PublicKey:
		switch pub.Params().Name {
		case "P-256":
			return "ES256", crypto.SHA256
		case "P-384":
			return "ES384", crypto.SHA384
		case "P-521":
			return "ES512", crypto.SHA512
		}
	}
	return "", 0
}

// JWKThumbprint creates a JWK thumbprint out of pub
// as specified in https://tools.ietf.org/html/rfc7638.
func JWKThumbprint(pub crypto.PublicKey) (string, error) {
	jwk, err := jwkEncode(pub)
	if err != nil {
		return "", err
	}
	b := sha256.Sum256([]byte(jwk))
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// jwsSign signs the digest using the given key.
// The hash is unused for ECDSA keys.
func jwsSign(key crypto.Signer, hash crypto.Hash, digest []byte) ([]byte, error) {
	switch pub := key.Public().(type) {
	case *rsa.PublicKey:
		return key.Sign(rand.Reader, digest, hash)
	case *ecdsa.PublicKey:
		sigASN1, err := key.Sign(rand.Reader, digest, hash)
		if err != nil {
			return nil, err
		}

		var rs struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(sigASN1, &rs); err != nil {
			return nil, err
		}

		rb, sb := rs.R.Bytes(), rs.S.Bytes()
		size := pub.Params().BitSize / 8
		if size%8 > 0 {
			size++
		}
		sig := make([]byte, size*2)
		copy(sig[size-len(rb):], rb)
		copy(sig[size*2-len(sb):], sb)
		return sig, nil
	}
	return nil, ErrUnsupportedKey
}

var 	ErrUnsupportedKey = errors.New("unknown key type; only RSA and ECDSA are supported")


// jwkEncode encodes public part of an RSA or ECDSA key into a JWK.
// The result is also suitable for creating a JWK thumbprint.
// https://tools.ietf.org/html/rfc7517
func jwkEncode(pub crypto.PublicKey) (string, error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		// https://tools.ietf.org/html/rfc7518#section-6.3.1
		n := pub.N
		e := big.NewInt(int64(pub.E))
		// Field order is important.
		// See https://tools.ietf.org/html/rfc7638#section-3.3 for details.
		return fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`,
			base64.RawURLEncoding.EncodeToString(e.Bytes()),
			base64.RawURLEncoding.EncodeToString(n.Bytes()),
		), nil
	case *ecdsa.PublicKey:
		// https://tools.ietf.org/html/rfc7518#section-6.2.1
		p := pub.Curve.Params()
		n := p.BitSize / 8
		if p.BitSize%8 != 0 {
			n++
		}
		x := pub.X.Bytes()
		if n > len(x) {
			x = append(make([]byte, n-len(x)), x...)
		}
		y := pub.Y.Bytes()
		if n > len(y) {
			y = append(make([]byte, n-len(y)), y...)
		}
		// Field order is important.
		// See https://tools.ietf.org/html/rfc7638#section-3.3 for details.
		return fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`,
			p.Name,
			base64.RawURLEncoding.EncodeToString(x),
			base64.RawURLEncoding.EncodeToString(y),
		), nil
	}
	return "", ErrUnsupportedKey
}

// jwsEncodeJSON signs claimset using provided key and a nonce.
// The result is serialized in JSON format containing either kid or jwk
// fields based on the provided KeyID value.
//
// The claimset is marshalled using json.Marshal unless it is a string.
// In which case it is inserted directly into the message.
//
// If kid is non-empty, its quoted value is inserted in the protected header
// as "kid" field value. Otherwise, JWK is computed using jwkEncode and inserted
// as "jwk" field value. The "jwk" and "kid" fields are mutually exclusive.
//
// If nonce is non-empty, its quoted value is inserted in the protected header.
//
// See https://tools.ietf.org/html/rfc7515#section-7.
func jwsEncodeJSON(claimset interface{}, key crypto.Signer, kid KeyID, nonce, url string) ([]byte, error) {
	if key == nil {
		return nil, errors.New("nil key")
	}
	alg, sha := jwsHasher(key.Public())
	if alg == "" || !sha.Available() {
		return nil, ErrUnsupportedKey
	}
	headers := struct {
		Alg   string          `json:"alg"`
		KID   string          `json:"kid,omitempty"`
		JWK   json.RawMessage `json:"jwk,omitempty"`
		Nonce string          `json:"nonce,omitempty"`
		URL   string          `json:"url"`
	}{
		Alg:   alg,
		Nonce: nonce,
		URL:   url,
	}
	switch kid {
	case noKeyID:
		jwk, err := jwkEncode(key.Public())
		if err != nil {
			return nil, err
		}
		headers.JWK = json.RawMessage(jwk)
	default:
		headers.KID = string(kid)
	}
	phJSON, err := json.Marshal(headers)
	if err != nil {
		return nil, err
	}
	phead := base64.RawURLEncoding.EncodeToString([]byte(phJSON))
	var payload string
	if val, ok := claimset.(string); ok {
		payload = val
	} else {
		cs, err := json.Marshal(claimset)
		if err != nil {
			return nil, err
		}
		payload = base64.RawURLEncoding.EncodeToString(cs)
	}
	hash := sha.New()
	hash.Write([]byte(phead + "." + payload))
	sig, err := jwsSign(key, sha, hash.Sum(nil))
	if err != nil {
		return nil, err
	}
	enc := JWS {
		Protected: phead,
		Payload:   payload,
		Sig:       base64.RawURLEncoding.EncodeToString(sig),
	}
	return json.Marshal(&enc)
}

// KeyID is the account key identity provided by a CA during registration.
type KeyID string

// noKeyID indicates that jwsEncodeJSON should compute and use JWK instead of a KID.
// See jwsEncodeJSON for details.
const noKeyID = KeyID("")

// noPayload indicates jwsEncodeJSON will encode zero-length octet string
// in a JWS request. This is called POST-as-GET in RFC 8555 and is used to make
// authenticated GET requests via POSTing with an empty payload.
// See https://tools.ietf.org/html/rfc8555#section-6.3 for more details.
const noPayload = ""

// noNonce indicates that the nonce should be omitted from the protected header.
// See jwsEncodeJSON for details.
const noNonce = ""
