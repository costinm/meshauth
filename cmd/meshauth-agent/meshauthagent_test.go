package main

import (
	"context"
	"github.com/ghodss/yaml"
	"io/ioutil"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/costinm/meshauth"
)

// e2e test - requires a project that is SetupAgent in GCP
//   - A GSA named k8s-NAMESPACE created for each supported namespace
//   - a kubeconfig with the default SetupAgent to a KSA with TokenRequest permission
//     for default@NAMESPACE
//   - permissions for the given token
func TestAgent(t *testing.T) {
	ctx := context.Background()

	cfile, err := os.ReadFile("../../testdata/alice/testenv.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{}
	err = yaml.Unmarshal(cfile, cfg)
	if err != nil {
		t.Fatal(err)
	}

	ma, err := SetupAgent(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Verify we can get access and ID tokens for GCP
	tp := ma.AuthProviders["gcp"]
	// email: k8s-NAMESPACE@PROJECT.iam.gserviceaccount.com, sub is an ID.
	tok, err := tp.GetToken(ctx, "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(meshauth.TokenPayload(tok), err)

	// Access token
	tok, err = tp.GetToken(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(tok[0:16], err)

	// Federated token
	ftp := ma.AuthProviders["gcp_fed"]
	tok, err = ftp.GetToken(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(tok[0:16], err)

	// K8S tokens
	ktp := ma.AuthProviders["k8s"]
	// email: k8s-NAMESPACE@PROJECT.iam.gserviceaccount.com, sub is an ID.
	tok, err = ktp.GetToken(ctx, "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(meshauth.TokenPayload(tok), err)

	// Test the HTTP interface
	// Start the metadata server
	//l, err := net.Listen("tcp", ":17014") // :0
	//l, err := net.Listen("tcp", ":0") // :0
	//if err != nil {
	//	t.Fatal(err)
	//}
	//go http.Serve(l, http.DefaultServeMux)
	//base := "http://" + l.Addr().String()
	base := "http://metadata"

	// Call the http interface
	req := httptest.NewRequest("GET", base+"/computeMetadata/v1/instance/service-accounts/default/identity?audience=ssh:", nil)
	req.Header.Add("Metadata-Flavor", "Google")

	res := httptest.NewRecorder()
	cfg.MainMux.ServeHTTP(res, req)

	data, err := ioutil.ReadAll(res.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(res.Result(), meshauth.TokenPayload(string(data)))
}
