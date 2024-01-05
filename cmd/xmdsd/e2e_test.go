package main

import (
	"context"
	"net/http"
	"testing"

	"github.com/costinm/meshauth"

	k8sc "github.com/costinm/mk8s/k8s"
)

// To avoid a yaml dependency, run:
// yq < ~/.kube/config -o json > ~/.kube/config.json
// See examples for additional configurations needed for the cluster.
// The tests should be run with a kube config pointing to a GKE cluster with the required configs.

func checkJWT(t *testing.T, jwt string) {

	r, _ := http.NewRequest("GET", "http://example", nil)
	// Expired key - issue a new one
	r.Header["Authorization"] = []string{"bearer " + jwt}

	// Example of google JWT in cloudrun:
	// eyJhbGciOiJSUzI1NiIsImtpZCI6IjBlNzJkYTFkZjUwMWNhNmY3NTZiZjEwM2ZkN2M3MjAyOTQ3NzI1MDYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIzMjU1NTk0MDU1OS5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1ZCI6IjMyNTU1OTQwNTU5LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTA0MzY2MjYxNjgxNjMwMTM4NTIzIiwiZW1haWwiOiJjb3N0aW5AZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJ1MTIwMzhrTTh2THcyZGN0dnVvbTdBIiwiaWF0IjoxNzAwODg0MDAwLCJleHAiOjE3MDA4ODc2MDB9.SIGNATURE_REMOVED_BY_GOOGLE"

	cfg := &meshauth.AuthConfig{}

	cfg.Issuers = []*meshauth.TrustConfig{{Issuer: "https://accounts.google.com"}}

	ja := meshauth.NewAuthn(cfg)

	// May use a custom method too with lower deps
	//ja.Verify = oidc.Verify

	err := ja.Auth(nil, r)
	if err != nil {
		t.Fatal(err)
	}
}

// Test starting with K8S credentials
// On a pod or a VM/dev with a kubeconfig file.
func TestK8SLite(t *testing.T) {
	ctx := context.Background()

	// Bootstrap K8S - get primary and secondary clusters.
	def := k8sc.NewK8S(&k8sc.K8SConfig{
		Namespace: "default",
		KSA:       "default",
	})
	err := def.InitK8SClient(ctx)
	if err != nil {
		t.Skip("Can't find a kube config file", err)
	}

	t.Run("K8S istio-ca tokens", func(t *testing.T) {
		// Will use the namespace/ksa from the config
		istiocaTok, err := def.GetToken(ctx, "Foo")
		if err != nil {
			t.Fatal(err)
		}
		_, istiocaT, _, _, _ := meshauth.JwtRawParse(istiocaTok)
		t.Log(istiocaT)
		if istiocaT != nil {
			t.Log(string(istiocaT.Payload))
		}
	})

	t.Run("K8S audience tokens", func(t *testing.T) {
		// Without audience overide - K8SCluster is a TokenSource as well
		tok, err := def.GetToken(ctx, "http://example.com")
		if err != nil {
			t.Error("Getting tokens with audience from k8s", err)
		}

		_, tokT, _, _, _ := meshauth.JwtRawParse(tok)
		t.Log(tokT)
	})

	projectID, _, _ := def.Default.GcpInfo()

	t.Run("K8S GCP federated tokens", func(t *testing.T) {
		sts1 := meshauth.NewFederatedTokenSource(&meshauth.STSAuthConfig{
			AudienceSource: projectID + ".svc.id.goog",
			//ClusterAddress: fmt.Sprintf("https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s",
			//	projectId, clusterLocation, clusterName),

			// Will use TokenRequest to get tokens with AudOverride
			TokenSource: def.Default,
		})
		tok, err := sts1.GetToken(ctx, "http://example.com")
		if err != nil {
			t.Error(err)
		}
		t.Log("Federated access token", tok)

	})

}
