package cmd

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/costinm/meshauth"
	"github.com/costinm/meshauth/pkg/oidc"
	"github.com/costinm/meshauth/pkg/uk8s"
	gke "github.com/costinm/mk8s/gcp"
	"sigs.k8s.io/yaml"
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
	ja.Verify = oidc.Verify

	err := ja.Auth(nil, r)
	if err != nil {
		t.Fatal(err)
	}
}

// Use GCP credentials from gcloud as trust source.
func TestGCP(t *testing.T) {
	ctx, cf := context.WithTimeout(context.Background(), 5*time.Second)
	defer cf()
	mauth := meshauth.NewMeshAuth(nil) // default

	// bootstrap with GCP credentials. Source of trust is a google account from file or MDS.
	// The local GSA  must have IAM permissions for the k8s-istio-system GSA, which is
	// mapped to default.istio-system
	// It must also have GKE permissions.
	//
	// If test runs in GCP/GKE/CR - will use MDS, otherwise ADC.
	err := gke.GcpInit(ctx, mauth, "k8s-istio-system@dmeshgate.iam.gserviceaccount.com")
	if err != nil {
		t.Skip("Skipping test, no GCP creds", err)
	}

	// GcpInit will set the 'gcp' provider.
	ts := mauth.AuthProviders["gcp"]

	access, err := ts.GetToken(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Token", "access", access[0:7])

	istio_ca, err := ts.GetToken(ctx, "istio_ca")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Token", "jwt", istio_ca)

	checkJWT(t, istio_ca)

	// GcpInit should also populate project ID.
	t.Log("Meta", "projectID", mauth.MDS.ProjectID())

	//base := "https://xmdsd-yydsuf6tpq-uc.a.run.app"

}

// Test starting with a self-signed root CA (local tests or 'depenency free'/disconnected)
// The test also matches the meshca binary.
func xTestPrivateCA(t *testing.T) {
	ctx, cf := context.WithTimeout(context.Background(), 5*time.Second)
	defer cf()

	// Init the CA - this normally runs on a remote server with ACME certs.
	ca := meshauth.CAFromEnv("../testdata/ca")

	mauth := ca.NewID("istio-system", "istiod", nil)

	// An MDS server should be able to proxy OIDC and know/cache JWK.
	http.HandleFunc("/.well-known/openid-configuration", mauth.HandleDisc)
	http.HandleFunc("/.well-known/jwks", mauth.HandleJWK)

	// TODO: init a per-node intermediate CA that can sign tokens for the node or cluster.

	// Use the private CA server to get a token and initialize a client
	istio_ca, err := mauth.MDS.GetToken(ctx, "istio-ca")
	if err != nil {
		t.Fatal(err)
	}
	checkJWT(t, istio_ca)

}

// Test starting with K8S credentials
// On a pod or a VM/dev with a kubeconfig file.
func TestK8SLite(t *testing.T) {
	ctx := context.Background()

	// Bootstrap K8S - get primary and secondary clusters.
	def, extra, err := uk8s.KubeFromEnv()

	if err != nil || def == nil {
		t.Skip("Can't find a kube config file", err)
	}

	if extra != nil {
		t.Log("Additional clusters", len(extra))
	}

	// Tokens using istio-ca audience for Istio - this is what Citadel and Istiod expect
	catokenS := def.NewK8STokenSource("istio-ca")

	t.Run("K8S istio-ca tokens", func(t *testing.T) {
		istiocaTok, err := catokenS.GetToken(ctx, "Foo")
		if err != nil {
			t.Error(err)
		}
		_, istiocaT, _, _, _ := meshauth.JwtRawParse(istiocaTok)
		t.Log(istiocaT)
		t.Log(string(istiocaT.Raw))
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

	t.Run("K8S GCP federated tokens", func(t *testing.T) {
		sts1, err := def.GCPFederatedSource(ctx)
		tok, err := sts1.GetToken(ctx, "http://example.com")
		if err != nil {
			t.Error(err)
		}
		t.Log("Federated access token", tok)
		grpcT, err := sts1.GetRequestMetadata(ctx, "https://example2.com")
		if err != nil {
			t.Error(err)
		}
		t.Log("Federated access token grpc ", grpcT)
	})

	t.Run("STS server, local", func(t *testing.T) {
		testSTS(t, -1, def)
	})

}

func loadKubeconfig() (*uk8s.KubeConfig, error) {
	kc := os.Getenv("KUBECONFIG")
	if kc == "" {
		kc = os.Getenv("HOME") + "/.kube/config"
	}
	kconf := &uk8s.KubeConfig{}

	var kcd []byte
	if kc != "" {
		if _, err := os.Stat(kc + ".json"); err == nil {
			// Explicit kube config, using it.
			kcd, err = ioutil.ReadFile(kc + ".json")
			if err != nil {
				return nil, err
			}
			err := json.Unmarshal(kcd, kconf)
			if err != nil {
				return nil, err
			}

			return kconf, nil

		} else if _, err := os.Stat(kc); err == nil {
			// Explicit kube config, using it.
			// 	"sigs.k8s.io/yaml"
			kcd, err = ioutil.ReadFile(kc)
			if err != nil {
				return nil, err
			}
			err := yaml.Unmarshal(kcd, kconf)
			if err != nil {
				return nil, err
			}

			return kconf, nil
		}
	}
	return nil, nil
}

func testSTS(t *testing.T, port int, def *uk8s.K8SCluster) {
	// An STS server returning K8S tokens
	sts := meshauth.NewSTS(&meshauth.STSAuthConfig{
		TokenSource: def,
	})

	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal("Listen")
	}

	mds := &meshauth.MDS{}

	mux := &http.ServeMux{}
	mux.Handle("/v1/token", sts)
	mux.Handle("/computeMetadata/v1/", mds)
	go http.Serve(l, mux)

	// Will get K8S tokens to authenticate, with istio-ca audience
	stsc := meshauth.NewSTS(&meshauth.STSAuthConfig{
		STSEndpoint: "http://" + l.Addr().String() + "/v1/token",
		TokenSource: def.NewK8STokenSource("istio-ca"),
	})

	ctx := context.Background()
	_, err = stsc.GetToken(ctx, "http://foo.com")
	if err != nil {
		t.Fatal("STSc token ", err)
	}

	mdsc := &meshauth.MDS{
		Addr: "http://" + l.Addr().String() + "/computeMetadata/v1",
	}

	_, err = mdsc.GetToken(ctx, "http://foo.com")
	if err != nil {
		t.Fatal("getting token from MDS", err)
	}
}
