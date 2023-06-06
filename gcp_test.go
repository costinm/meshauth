//go:build !NO_VENDOR
// +build !NO_VENDOR

package meshauth

import (
	"context"
	"log"
	"testing"
)

func TestGCP(t *testing.T) {
	kconf, err := loadKubeconfig()
	if err != nil {
		t.Skip("Can't find a kube config file")
	}

	ctx := context.Background()
	def, extra, err := InitK8S(ctx, kconf)

	if extra != nil {
		t.Log("Additional clusters", len(extra))
	}

	if err != nil {
		t.Skip("Can't find a kube config file")
	}

	// Tokens using istio-ca audience for Istio - this is what Citadel and Istiod expect
	//catokenS := def.NewK8STokenSource("istio-ca")

	t.Run("K8S GCP ID tokens", func(t *testing.T) {
		atd, err := def.GCPAccessTokenSource("")
		tok, err := atd.GetToken(ctx, "http://example.com")
		if err != nil {
			t.Error(err)
		}
		_, tokT, _, _, _ := JwtRawParse(tok)
		t.Log(tokT)

		tok, err = atd.GetToken(ctx, "")
		if err != nil {
			t.Error(err)
		}
		t.Log("Delegated user access token", tok)
	})

	t.Run("K8S GCP access tokens - ASM", func(t *testing.T) {
		atd, err := def.GCPAccessTokenSource("")
		tok, err := atd.GetToken(ctx, "")
		if err != nil {
			t.Error(err)
		}
		t.Log("Delegated user access token", tok)
	})

	t.Run("secret", func(t *testing.T) {
		atd, err := def.GCPAccessTokenSource("")
		tok, err := atd.GetToken(ctx, "")
		if err != nil {
			t.Error(err)
		}
		cd, err := atd.GetSecret(ctx, tok, def.ProjectID, "ca", "1")
		if err != nil {
			t.Fatal(err)
		}
		log.Println(string(cd))
	})

}
