package meshauth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Auth in hbone is primarily mTLS-based, but in some cases JWTs are used.
// Few minimal helper functions to avoid deps and handle k8s-specific variant.

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
	Sub string `json:"sub,omitempty"`

	// Max 24h
	Exp int64 `json:"exp,omitempty"`
	IAT int64 `json:"iat,omitempty"`

	// Issuer - for example kubernetes/serviceaccount.
	Iss string `json:"iss,omitempty"`

	Email string `json:"email,omitempty"`

	EmailVerified bool `json:"email_verified,omitempty"`

	K8S K8SAccountInfo `json:"kubernetes.io"`

	Name string `json:"kubernetes.io/serviceaccount/service-account.name"`

	Raw string `json:-`
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

func DecodeJWT(jwt string) *JWT {
	payload := TokenPayload(jwt)
	j := &JWT{}
	_ = json.Unmarshal([]byte(payload), j)
	return j
}
