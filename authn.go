package meshauth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Minimal implementatio of OIDC, matching K8S. Other helpers for platform-specific tokens.
// Also includes RequestAuthentication/TrustConfig support based on Istio API.
//
// A more common option is github.com/coreos/go-oidc, which depends on
// gopkg.in/square/go-jose.v2 The meshauth/oidc package is using that library to download
// and convert the public keys.

//
// GCP also uses (https://github.com/GoogleCloudPlatform/secrets-store-csi-driver-provider-gcp/blob/v0.2.0/auth/auth.go):
// https://securetoken.googleapis.com/v1/identitybindingtoken
// "serviceAccount:<project>.svc.id.goog[<namespace>/<sa>]"
//
// In Istio, the WorkloadID token can be exchanged for access tokens:
// POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/
// service-<GCP project number>@gcp-sa-meshdataplane.iam.gserviceaccount.com:generateAccessToken
// Content-Type: application/json
// Authorization: Bearer <federated token>
// {
//  "Delegates": [],
//  "Scope": [
//      https://www.googleapis.com/auth/cloud-platform
//  ],
// }
//
// curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/my-gsa@my-project.iam.gserviceaccount.com/token"
// -H'Metadata-Flavor:Google'
//
// Access tokens:
// https://developers.google.com/identity/toolkit/reference/securetoken/rest/v1/token
// POST https://securetoken.googleapis.com/v1/token
// grant_type=authorization_code&code=ID_TOKEN
// grant_type=refresh_token&refresh_token=TOKEN
// Resp: {
//  "access_token": string,
//  "expires_in": string,
//  "token_type": string,
//  "refresh_token": string,
//}
//
//

type Authn struct {
	Cfg *AuthConfig

	Verify func(context.Context, *TrustConfig, string) error
	Init   func(context.Context, *TrustConfig) error

	rules map[string]*TrustConfig `json:-`
}

func NewAuthn(cfg *AuthConfig) *Authn {
	if cfg == nil {
		cfg = &AuthConfig{}
	}
	an := &Authn{Cfg: cfg, rules: map[string]*TrustConfig{}}
	for _, v := range cfg.Issuers {
		an.rules[v.Issuer] = v
	}

	return an
}

// CheckJwt will validate the JWT and return the 'sub' (subject) of the token.
// Not an error if no auth found - only if the token is invalid.
// The identity will only be set if authenticated.
// Authz may reject the request if it is missing authn
func (ja *Authn) CheckJwt(token string) (jwt *JWT, e error) {

	_, idt, _, _, err := JwtRawParse(token)
	if err != nil {
		return nil, err
	}

	if ja.Cfg.CloudrunIAM && idt.Iss == "https://accounts.google.com" {
		// Special case: Cloudrun IAM will check the token and forward it without signature.
		slog.Info("IAM JWT", "tok", idt)
		return idt, nil
	}

	// 1. Identity the 'issuer'.

	authnRule := ja.rules[idt.Iss]
	if authnRule == nil {
		return nil, errors.New("Unknown issuer " + idt.Iss)
	}

	err = ja.Verify(context.Background(), authnRule, token)
	if err == nil {
		//claims := &k8sClaims{}
		//idt.Claims(claims)
		//
		//allclaims := map[string]interface{}{}
		//idt.Claims(allclaims)

		slog.Info("AuthJwt", "token", idt, "iss", idt.Iss,
			"aud", idt.Aud, "sub", idt.Sub) // , "tok", string(password))

		return idt, nil
	} else {
		slog.Info("JWT failed", "error", err, "attempted", idt)
		e = err
	}
	return
}

const BearerPrefix = "Bearer "

// Authn extracts credentials from request, applies the authn rules to extact claims and
// sets the result in headers and context.
func (ja *Authn) Auth(actx *AuthContext, r *http.Request) error {
	a := r.Header["Authorization"]
	if len(a) == 0 {
		return nil
	}
	rawa := strings.TrimSpace(a[0])

	if strings.HasPrefix(rawa, BearerPrefix) ||
		strings.HasPrefix(rawa, "bearer ") { // cloudrun is lower case for some reason
		t := rawa[7:]
		jt, err := ja.CheckJwt(t)
		if err != nil {
			return err
		}

		if jt.Email != "" {
			r.Header["X-User"] = []string{jt.Email}
		} else {
			r.Header["X-User"] = []string{jt.Sub}
		}
	} else if strings.HasPrefix(rawa, "vapid") {
		tok, pub, err := CheckVAPID(rawa, time.Now())
		if err != nil {
			return err
		}
		r.Header["X-VAPID-Pub"] = []string{string(pub)}
		r.Header["X-VAPID-Sub"] = []string{tok.Sub}

	}
	return nil
}

// WIP: discovery document returned when fetching the 'issuer' well known location
//
//	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
//
// Example: curl -v https://accounts.google.com/.well-known/openid-configuration
type OIDCDiscDoc struct {
	// Should match the one in the URL
	Issuer string `json:"issuer"`

	// Same as the URI in the Istio config - contains the keys.
	// Example: "https://www.googleapis.com/oauth2/v3/certs"
	JWKSURL string `json:"jwks_uri"`

	// Not used
	AuthURL       string `json:"authorization_endpoint"`
	DeviceAuthURL string `json:"device_authorization_endpoint"`
	TokenURL      string `json:"token_endpoint"`
	UserInfoURL   string `json:"userinfo_endpoint"`

	Algorithms []string `json:"id_token_signing_alg_values_supported"`
}
