package meshauth

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/costinm/meshauth/k8s"

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
	istiocaTok, err := catokenS.GetToken(ctx, "Foo")
	if err != nil {
		t.Error(err)
	}
	_, istiocaT, _, _, _ := JwtRawParse(istiocaTok)
	t.Log(istiocaT)

	// Without audience overide - K8SCluster is a TokenSource as well
	tok, err := def.GetToken(ctx, "http://example.com")
	if err != nil {
		t.Error(err)
	}

	_, tokT, _, _, _ := JwtRawParse(tok)
	t.Log(tokT)

	// Now attempt to get the mesh-env config map from cluster, where we expect GCP settings
	// This is only needed if we want to create federated tokens using K8S

	err = def.LoadMeshEnv(ctx)
	if err != nil {
		t.Fatal(err)
	}

	sts1, err := def.GCPFederatedSource(ctx)
	tok, err = sts1.GetToken(ctx, "http://example.com")
	if err != nil {
		t.Error(err)
	}
	t.Log("Federated access token", tok)

	atd, err := def.GCPAccessTokenSource(ctx)
	tok, err = atd.GetToken(ctx, "http://example.com")
	if err != nil {
		t.Error(err)
	}
	_, tokT, _, _, _ = JwtRawParse(tok)
	t.Log(tokT)

	tok, err = atd.GetToken(ctx, "")
	if err != nil {
		t.Error(err)
	}
	t.Log("Delegated user access token", tok)
}

func loadKubeconfig() (*k8s.KubeConfig, error) {
	kc := os.Getenv("KUBECONFIG")
	if kc == "" {
		kc = os.Getenv("HOME") + "/.kube/config"
	}
	kconf := &k8s.KubeConfig{}

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
