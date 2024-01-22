package oidc

import (
	"encoding/json"
	"github.com/costinm/meshauth"
	"gopkg.in/square/go-jose.v2"
)

// github.com/coreos/go-oidc library wraps square/go-jose.v2 - it has code to download the JWKS
// from the OIDC well known location.
//
// It has some google-specific code, but mainly uses keySet.VerifySignature.

func ConvertJWKS(i *meshauth.TrustConfig) error {
	body := []byte(i.Jwks)

	var keySet jose.JSONWebKeySet
	err := json.Unmarshal(body, &keySet)
	if err != nil {
		return err
	}

	// Map of 'kid' to key
	i.KeysByKid = map[string]interface{}{}
	for _, ks := range keySet.Keys {
		i.KeysByKid[ks.KeyID] = ks.Key
	}
	
	return nil
}
