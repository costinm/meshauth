package cmd

import (
	"context"
	"io/ioutil"
	"net/http"
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
func TestGetToken(t *testing.T) {
	ctx := context.Background()
	proj := os.Getenv("PROJECT_ID")
	if proj == "" {
		t.Skip("Missing PROJECT_ID")
	}
	ns := os.Getenv("NAMESPACE")
	if ns == "" {
		ns = "default"
	}

	ma, err := SetupAgent(ctx, &Config{
		MeshAuthCfg: meshauth.MeshAuthCfg{
			TrustDomain: "",
			ProjectID:   proj,
			Namespace:   ns,
			Name:        "default",
			// email field in returned token, sub is an ID
			GSA: "k8s-" + ns + "@" + proj + ".iam.gserviceaccount.com",
		}})
	if err != nil {
		t.Fatal(err)
	}

	// Direct access to the MDSAgent providers
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

	// Test the HTTP interface
	// Start the metadata server
	//l, err := net.Listen("tcp", ":17014") // :0
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
	http.DefaultServeMux.ServeHTTP(res, req)

	data, err := ioutil.ReadAll(res.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(res.Result(), meshauth.TokenPayload(string(data)))
}
