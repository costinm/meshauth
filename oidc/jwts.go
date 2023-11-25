package oidc

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/costinm/meshauth"
	"gopkg.in/square/go-jose.v2"
)

func Verify(ctx context.Context, v *meshauth.JWTRule, raw string) error {
	var ver *oidc.IDTokenVerifier
	if v.Key == nil {
		if len(v.JwksUri) > 0 {
			keySet := oidc.NewRemoteKeySet(context.Background(), v.JwksUri)
			ver = oidc.NewVerifier(v.Issuer, keySet, &oidc.Config{SkipClientIDCheck: true})
		} else {
			// Use Issuer directly to download the OIDC document and extract the JwksUri
			provider, err := oidc.NewProvider(context.Background(), v.Issuer)
			if err != nil {
				// OIDC discovery may fail, e.g. http request for the OIDC server may fail.
				// Instead of a permanent failre, this will be done on-demand, so other providers
				// may continue to work.
				slog.Info("Issuer not found, skipping", "iss", v, "error", err)
				return err
			}
			ver = provider.Verifier(&oidc.Config{SkipClientIDCheck: true})
		}
		v.Key = ver
	}

	if ver, ok := v.Key.(*oidc.IDTokenVerifier); ok {
		_, err := ver.Verify(ctx, raw)
		return err
	}

	return nil
}

func Init(ctx context.Context, v meshauth.JWTRule) error {
	var ver *oidc.IDTokenVerifier
	if v.Key == nil {
		if len(v.JwksUri) > 0 {
			keySet := oidc.NewRemoteKeySet(context.Background(), v.JwksUri)
			ver = oidc.NewVerifier(v.Issuer, keySet, &oidc.Config{SkipClientIDCheck: true})
		} else {
			// Use Issuer directly to download the OIDC document and extract the JwksUri
			provider, err := oidc.NewProvider(context.Background(), v.Issuer)
			if err != nil {
				// OIDC discovery may fail, e.g. http request for the OIDC server may fail.
				// Instead of a permanent failre, this will be done on-demand, so other providers
				// may continue to work.
				slog.Info("Issuer not found, skipping", "iss", v, "error", err)
				return err
			}
			ver = provider.Verifier(&oidc.Config{SkipClientIDCheck: true})
		}
		v.Key = ver
	}
	return nil
}

type JWTAuth struct {
	Cfg          *meshauth.AuthConfig
	jwtProviders map[string]*oidc.IDTokenVerifier
}

// JoseVerifier uses go-jose directly
type JoseVerifier struct {
	keySet jose.JSONWebKeySet
}

func NewNJWTAuth(cfg *meshauth.AuthConfig) *JWTAuth {
	if cfg == nil {
		// TODO: Trust only our own root CA
		cfg = &meshauth.AuthConfig{}
	}
	ja := &JWTAuth{Cfg: cfg, jwtProviders: map[string]*oidc.IDTokenVerifier{}}
	ja.InitJWT()
	return ja
}

// Init the JWT map - can be used to reconfigure.
func (ja *JWTAuth) InitJWT() {
	if len(ja.Cfg.Issuers) == 0 {
		return
	}
	for _, v := range ja.Cfg.Issuers {
		// Code from Istio Citade and Istiod Auth
		if len(v.JwksUri) > 0 {
			keySet := oidc.NewRemoteKeySet(context.Background(), v.JwksUri)
			ja.jwtProviders[v.Issuer] = oidc.NewVerifier(v.Issuer, keySet, &oidc.Config{SkipClientIDCheck: true})
			continue
		}
		// Use Issuer directly to download the OIDC document and extract the JwksUri
		provider, err := oidc.NewProvider(context.Background(), v.Issuer)
		if err != nil {
			// OIDC discovery may fail, e.g. http request for the OIDC server may fail.
			// Instead of a permanent failre, this will be done on-demand, so other providers
			// may continue to work.
			slog.Info("Issuer not found, skipping", "iss", v, "error", err)
			continue
		}
		// No ClientID field
		verifier := provider.Verifier(&oidc.Config{SkipClientIDCheck: true})
		ja.jwtProviders[v.Issuer] = verifier
	}
}

// CheckJwt will validate the JWT and return the 'sub' (subject) of the token.
// Not an error if no auth found - only if the token is invalid.
// The identity will only be set if authenticated.
// Authz may reject the request if it is missing authn
func (ja *JWTAuth) CheckJwt(token string) (jwt *meshauth.JWT, e error) {

	_, jwtRaw, _, _, err := meshauth.JwtRawParse(token)
	if err != nil {
		return nil, err
	}

	if ja.Cfg.CloudrunIAM && jwtRaw.Iss == "https://accounts.google.com" {
		// Special case: Cloudrun IAM will check the token and forward it without signature.
		slog.Info("IAM JWT", "tok", jwtRaw)
		return jwtRaw, nil
	}

	// 1. Identity the 'issuer'.

	verifier := ja.jwtProviders[jwtRaw.Iss]
	if verifier == nil {
		return nil, errors.New("Unknown issuer " + jwtRaw.Iss)
	}

	idt, err := verifier.Verify(context.Background(), token)
	if err == nil {
		//claims := &k8sClaims{}
		//idt.Claims(claims)
		//
		//allclaims := map[string]interface{}{}
		//idt.Claims(allclaims)

		slog.Info("AuthJwt", "token", jwtRaw, "iss", idt.Issuer,
			"aud", idt.Audience, "sub", idt.Subject) // , "tok", string(password))

		return jwtRaw, nil
	} else {
		slog.Info("JWT failed", "error", err, "attempted", jwtRaw)
		e = err
	}
	return
}

const BearerPrefix = "Bearer "

func (ja *JWTAuth) Auth(r *http.Request) error {
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
		tok, pub, err := meshauth.CheckVAPID(rawa, time.Now())
		if err != nil {
			return err
		}
		r.Header["X-VAPID-Pub"] = []string{string(pub)}
		r.Header["X-VAPID-Sub"] = []string{tok.Sub}

	}
	return nil
}
