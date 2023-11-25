package oidc

import (
	"context"
	"log/slog"

	"github.com/coreos/go-oidc"
	"github.com/costinm/meshauth"
	"gopkg.in/square/go-jose.v2"
)

func Verify(ctx context.Context, v *meshauth.JWTRule, raw string) error {
	if v.Key == nil {
		err := Init(ctx, v)
		if err != nil {
			return err
		}
	}

	if ver, ok := v.Key.(*oidc.IDTokenVerifier); ok {
		_, err := ver.Verify(ctx, raw)
		return err
	}

	return nil
}

// Process a JWTRule and attempt to populate the PEM key
func Init(ctx context.Context, v *meshauth.JWTRule) error {
	var ver *oidc.IDTokenVerifier
	if v.Key == nil {
		if len(v.JwksUri) > 0 {
			keySet := oidc.NewRemoteKeySet(context.Background(), v.JwksUri)
			// oidc.KeySet embed and refresh cached jose.JSONWebKey
			// It is unfortunately just an interface - doesn't expose the actual keys.
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

// JoseVerifier uses go-jose directly
type JoseVerifier struct {
	keySet jose.JSONWebKeySet
}
