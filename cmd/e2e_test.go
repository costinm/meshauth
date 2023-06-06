package cmd

import (
	"context"
	"encoding/json"
	"gcp"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/costinm/meshauth"
	"sigs.k8s.io/yaml"
)

// To avoid a yaml dependency, run:
// yq < ~/.kube/config -o json > ~/.kube/config.json
// See examples for additional configurations needed for the cluster.
// The tests should be run with a kube config pointing to a GKE cluster with the required configs.

// Use GCP credentials from gcloud as trust source.
func TestGCP(t *testing.T) {
	ctx, cf := context.WithTimeout(context.Background(), 5*time.Second)
	defer cf()
	ms := meshauth.NewMeshAuth(nil) // default
	mds := ms.MDS

	// bootstrap with GCP credentials. Source of trust is a google account from file or MDS.
	err := gcp.GcpInit(ctx, ms, "k8s-istio-system@dmeshgate.iam.gserviceaccount.com")
	if err != nil {
		t.Skip("Skipping test, no GCP creds", err)
	}

	// If test runs in GCP/GKE/CR - will use MDS, otherwise ADC.

	ts := ms.AuthProviders["gcp"]

	access, err := ts.GetToken(ctx, "")
	t.Log("Token", "access", access, "err", err)

	istio_ca, err := ts.GetToken(ctx, "istio_ca")
	t.Log("Token", "access", istio_ca, "err", err)

	t.Log("Meta", "projectID", mds.ProjectID())

}

// Test starting with a real K8S client.
func TestK8S(t *testing.T) {
}

// Test starting with a self-signed root CA (local tests or 'depenency free'/disconnected)
// The test also matches the meshca binary.
func TestPrivateCA(t *testing.T) {
	ctx, cf := context.WithTimeout(context.Background(), 5*time.Second)
	defer cf()

	// Init the CA - this normally runs on a remote server with ACME certs.
	ca := meshauth.CAFromEnv("../testdata/ca")
	ma := ca.NewID("istio-system", "istiod")

	http.HandleFunc("/.well-known/openid-configuration", ma.HandleDisc)
	http.HandleFunc("/.well-known/jwks", ma.HandleJWK)

	// TODO: init a per-node intermediate CA that can sign tokens for the node or cluster.

	// Use the private CA server to get a token and initialize a client
	ma.MDS.GetToken(ctx, "istio-ca")

}

// Test starting with K8S credentials
// On a pod or a VM/dev with a kubeconfig file.
func TestK8SLite(t *testing.T) {
	kconf, err := loadKubeconfig()
	if err != nil {
		t.Skip("Can't find a kube config file")
	}

	ctx := context.Background()

	// Bootstrap K8S - get primary and secondary clusters.
	def, extra, err := meshauth.InitK8S(ctx, kconf)

	if err != nil {
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

func loadKubeconfig() (*meshauth.KubeConfig, error) {
	kc := os.Getenv("KUBECONFIG")
	if kc == "" {
		kc = os.Getenv("HOME") + "/.kube/config"
	}
	kconf := &meshauth.KubeConfig{}

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

func testSTS(t *testing.T, port int, def *meshauth.K8SCluster) {
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
