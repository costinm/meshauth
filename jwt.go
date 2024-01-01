package meshauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Few minimal helper functions to avoid deps and handle k8s-specific variants.
// Goal is to also compile to WASM - common library is go-jose.
//

// First part of the token.
type JWTHead struct {
	Typ string `json:"typ"`
	Alg string `json:"alg,omitempty"`
}

// JWT includes minimal field for a JWT, primarily for extracting iss for the exchange.
// This is used with K8S JWTs, which use multi-string.
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
	K8S K8SAccountInfo `json:"kubernetes.io"`

	Name string `json:"kubernetes.io/serviceaccount/service-account.name"`

	Raw string `json:"-"`
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
	Namespace string `json:"namespace"`
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
	if len(jwtSplit) != 3 {
		return ""
	}
	//azp,"email","exp":1629832319,"iss":"https://accounts.google.com","sub":"1118295...
	payload := jwtSplit[1]

	payloadBytes, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}

	return string(payloadBytes)
}

// DecodeJWT decodes the content of a token. No signature checks.
func DecodeJWT(jwt string) *JWT {
	payload := TokenPayload(jwt)
	j := &JWT{}
	_ = json.Unmarshal([]byte(payload), j)
	return j
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
	b.Raw = string(payload)

	if len(parts) > 2 {
		sig, _ = base64.RawURLEncoding.DecodeString(parts[2])
		// Allow invalid / missing signature - verify will check if needed
		// In some cases the gateway will wipe the sig.
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
