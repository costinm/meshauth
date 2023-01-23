package meshauth

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"testing"

	"sigs.k8s.io/yaml"
)

// To avoid a yaml dependency, run:
// yq < ~/.kube/config -o json > ~/.kube/config.json
// See examples for additional configurations needed for the cluster.
// The tests should be run with a kube config pointing to a GKE cluster with the required configs.

func TestK8S(t *testing.T) {
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
	catokenS := def.NewK8STokenSource("istio-ca")

	t.Run("K8S istio-ca tokens", func(t *testing.T) {
		istiocaTok, err := catokenS.GetToken(ctx, "Foo")
		if err != nil {
			t.Error(err)
		}
		_, istiocaT, _, _, _ := JwtRawParse(istiocaTok)
		t.Log(istiocaT)
		t.Log(string(istiocaT.Raw))
	})

	t.Run("K8S audience tokens", func(t *testing.T) {
		// Without audience overide - K8SCluster is a TokenSource as well
		tok, err := def.GetToken(ctx, "http://example.com")
		if err != nil {
			t.Error("Getting tokens with audience from k8s", err)
		}

		_, tokT, _, _, _ := JwtRawParse(tok)
		t.Log(tokT)
	})

	// Now attempt to get the mesh-env config map from cluster, where we expect GCP settings
	// This is only needed if we want to create federated tokens using K8S
	err = def.LoadMeshEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}

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

	t.Run("STS server, local", func(t *testing.T) {
		testSTS(t, -1, def)
	})

}

func loadKubeconfig() (*KubeConfig, error) {
	kc := os.Getenv("KUBECONFIG")
	if kc == "" {
		kc = os.Getenv("HOME") + "/.kube/config"
	}
	kconf := &KubeConfig{}

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

func testSTS(t *testing.T, port int, def *K8SCluster) {
	// An STS server returning K8S tokens
	sts := NewSTS(&STSAuthConfig{
		TokenSource: def,
	})

	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal("Listen")
	}

	mds := &MDS{
		TokenSource: def,
	}

	mux := &http.ServeMux{}
	mux.Handle("/v1/token", sts)
	mux.Handle("/computeMetadata/v1/", mds)
	go http.Serve(l, mux)

	// Will get K8S tokens to authenticate, with istio-ca audience
	stsc := NewSTS(&STSAuthConfig{
		STSEndpoint: "http://" + l.Addr().String() + "/v1/token",
		TokenSource: def.NewK8STokenSource("istio-ca"),
	})

	ctx := context.Background()
	_, err = stsc.GetToken(ctx, "http://foo.com")
	if err != nil {
		t.Fatal("STSc token ", err)
	}

	mdsc := &MDS{
		Addr: "http://" + l.Addr().String() + "/computeMetadata/v1",
	}

	_, err = mdsc.GetToken(ctx, "http://foo.com")
	if err != nil {
		t.Fatal("getting token from MDS", err)
	}
}
