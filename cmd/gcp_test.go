//go:build !NO_VENDOR
// +build !NO_VENDOR

package cmd

import (
	"context"
	"log"
	"testing"

	"github.com/costinm/meshauth"
	"github.com/costinm/meshauth/pkg/uk8s"
)

func TestGCP2(t *testing.T) {

	ctx := context.Background()
	def, extra, err := uk8s.KubeFromEnv()

	if extra != nil {
		t.Log("Additional clusters", len(extra))
	}

	if err != nil {
		t.Skip("Can't find a kube config file")
	}

	// Tokens using istio-ca audience for Istio - this is what Citadel and Istiod expect
	//catokenS := def.NewK8STokenSource("istio-ca")

	t.Run("K8S GCP muxID tokens", func(t *testing.T) {
		atd, err := uk8s.GCPAccessTokenSource(def, "")
		tok, err := atd.GetToken(ctx, "http://example.com")
		if err != nil {
			t.Error(err)
		}
		_, tokT, _, _, _ := meshauth.JwtRawParse(tok)
		t.Log(tokT)

		tok, err = atd.GetToken(ctx, "")
		if err != nil {
			t.Error(err)
		}
		t.Log("Delegated user access token", tok)
	})

	t.Run("K8S GCP access tokens - ASM", func(t *testing.T) {
		atd, err := uk8s.GCPAccessTokenSource(def, "")
		tok, err := atd.GetToken(ctx, "")
		if err != nil {
			t.Error(err)
		}
		t.Log("Delegated user access token", tok)
		tok, err = atd.GetToken(ctx, "https://example.com")
		if err != nil {
			t.Error(err)
		}
		t.Log("Delegated user access token", tok)
	})

	t.Run("ADC-user", func(t *testing.T) {
		// refresh token, quota_project_id - for the gcloud credentials.
		// On GCE will use MDS and get project ID too.
		//cfg1, err := google.FindDefaultCredentials(ctx)
		//log.Println(cfg1.ProjectID, string(cfg1.JSON))

		oa := uk8s.FindDefaultCredentials()
		log.Println(oa)

		tok, err := oa.Token(ctx, "http://example.com")
		log.Println(tok, err)

		log.Println(meshauth.DecodeJWT(tok))
	})

	t.Run("secret", func(t *testing.T) {
		atd, err := uk8s.GCPAccessTokenSource(def, "")
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
