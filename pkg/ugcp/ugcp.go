package ugcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/costinm/meshauth"
	"github.com/costinm/meshauth/pkg/tokens"
)

// Dependency-less GCP integration (for wasm and minimal clients)

// See golang.org/x/oauth2/google

// Subset of the generated GCP config - to avoid a dependency and bloat.
// This includes just what we need for bootstraping from GKE, Hub or secret store.
//
// There are few mechanisms to bootstrap GCP identity:
// 1. MDS - this is likely best for VM and CR, but on GKE requires annotating the KSA.
//    It does return a federated access token otherwise - but no JWT tokens. It can still be exchanged.
// 2. Downloaded service account key, with a private key to sign JWTs.
// 3. Gcloud config - returns a user account, can get access tokens and exchange for a GSA
// 4. Federated - best but hard to setup, starting with a K8S or any other OIDC provider.
//
// This file covers 1 and 4. For 2 and 3 - the gcp/ package provides a helper to bootstrap,
// using the golang oauth2 package as dependency.

// JWT authentication:
// For service accounts it is possible to download and upload a public key.
// Supports RSA in x509 cert for upload.
// The flow is:
// - generate a JWT signed by private key - no roundtrip needed
// - exchange the JWT using the normal process. oauth2.jwt package has example.
//

//
//```shell
//CMD="gcloud container clusters describe ${CLUSTER} --zone=${ZONE} --project=${PROJECT}"
//
//K8SURL=$($CMD --format='value(endpoint)')
//K8SCA=$($CMD --format='value(masterAuth.clusterCaCertificate)' )
//```
//
//```yaml
//apiVersion: v1
//kind: Config
//current-context: my-cluster
//contexts: [{name: my-cluster, context: {cluster: cluster-1, user: user-1}}]
//users: [{name: user-1, user: {auth-provider: {name: gcp}}}]
//clusters:
//- name: cluster-1
//  cluster:
//    server: "https://${K8SURL}"
//    certificate-authority-data: "${K8SCA}"
//
//```


// TODO: curl "https://oauth2.googleapis.com/tokeninfo?id_token=ID_TOKEN"
// curl "https://oauth2.googleapis.com/tokeninfo?access_token=ACCESS_TOKEN"



// STS provides token exchanges. Implements grpc and golang.org/x/oauth2.TokenSource
//
// The source of trust is the K8S or other IDP token with TrustDomain audience, it is exchanged with
// access or WorkloadID tokens.
type GCPAuth struct {
	TokenCache tokens.TokenCache

	TokenProvider tokens.TokenSource
	ProjectID string

	Debug bool
}

func (g *GCPAuth) Provision(ctx context.Context) error {
	if g.TokenProvider == nil {
		oa := FindDefaultCredentials()
		g.TokenProvider = oa
	}

	g.TokenCache = tokens.TokenCache{TokenSource: g.TokenProvider}

	return nil
}

// WIP - if GOOGLE_APPLICATION_CREDENTIALS is present, load it
// and use it as a source of access tokens instead of k8s.
// Same for MDS
func FindDefaultCredentials() *OAuth2Source {
	adc := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if adc == "" {
		adc = os.Getenv("HOME") + "/.config/gcloud/application_default_credentials.json"
		if _, err := os.Stat(adc); err != nil {
			adc = ""
		}
	}
	if adc != "" {
		b, err := ioutil.ReadFile(adc)
		if err == nil {
			cf := &OAuth2Source{}
			err = json.Unmarshal(b, cf)
			return cf
			// TODO: use refresh token and token_uri ("https://accounts.google.com/o/oauth2/token")
		}
	}
	return nil
}

// GKE2RestCluster gets all the clusters for a project, and returns Cluster object.
func (gcp *GCPAuth) GKEClusters(ctx context.Context) ([]*meshauth.Dest, error) {

	token, err := gcp.TokenCache.Token(ctx, "")
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://container.googleapis.com/v1/projects/"+gcp.ProjectID+"/locations/-/clusters", nil)
	req.Header.Add("authorization", "Bearer "+token)

	res, err := http.DefaultClient.Do(req)
	if res.StatusCode != 200 {
		rd, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%d %s", res.StatusCode, string(rd))
	}

	rd, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if gcp.Debug {
		log.Println(string(rd))
	}

	cl := &Clusters{}
	err = json.Unmarshal(rd, cl)
	if err != nil {
		return nil, err
	}

	rcl := []*meshauth.Dest{}

	for _, c := range cl.Clusters {
		rc := &meshauth.Dest{
			Addr:          "https://" + c.Endpoint + ":443",
			TokenProvider: gcp.TokenProvider,
			//muxID:            "gke_" + p + "_" + c.Location + "_" + c.Name,
		}
		rc.AddTrustPEM(c.MasterAuth.ClusterCaCertificate)

		rcl = append(rcl, rc)
	}

	return rcl, err
}

func (gcp *GCPAuth) HubClusters(ctx context.Context) ([]*meshauth.Dest, error) {

	token, err := gcp.TokenCache.Token(ctx, "")
	if err != nil {
		return nil, err
	}


	req, _ := http.NewRequest("GET",
		"https://gkehub.googleapis.com/v1/projects/"+gcp.ProjectID+"/locations/-/memberships", nil)
	req = req.WithContext(ctx)
	req.Header.Add("authorization", "Bearer "+token)

	res, err := http.DefaultClient.Do(req)
	if res.StatusCode != 200 {
		rd, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%d %s", res.StatusCode, string(rd))
	}
	rd, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if gcp.Debug {
		log.Println(string(rd))
	}

	cl := &HubClusters{}
	err = json.Unmarshal(rd, cl)
	if err != nil {
		return nil, err
	}
	rcl := []*meshauth.Dest{}

	for _, hc := range cl.Resources {
		// hc doesn't provide the endpoint. Need to query GKE - but instead of going over each cluster we can do
		// batch query on the project and filter.
		if hc.Endpoint != nil && hc.Endpoint.GkeCluster != nil {
			ca := hc.Endpoint.GkeCluster.ResourceLink
			if strings.HasPrefix(ca, "//container.googleapis.com") {
				rc, err := gcp.GKECluster(ctx, token, ca[len("//container.googleapis.com"):])
				if err != nil {
					log.Println("Failed to get ", ca, err)
				} else {
					rcl = append(rcl, rc)
				}
			}
		}
	}

	return rcl, err
}

// GetDest returns a cluster config using the GKE API. Path must follow GKE API spec: /projects/P/locations/L/l
func (gcp *GCPAuth) GKECluster(ctx context.Context, token string, path string) (*meshauth.Dest, error) {
	req, _ := http.NewRequest("GET", "https://container.googleapis.com/v1"+path, nil)
	req = req.WithContext(ctx)
	if token != "" {
		req.Header.Add("authorization", "Bearer "+token)
	}

	res, err := http.DefaultClient.Do(req)
	if res.StatusCode != 200 {
		rd, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%d %s", res.StatusCode, string(rd))
	}
	rd, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if gcp.Debug {
		log.Println(string(rd))
	}

	c := &Cluster{}
	err = json.Unmarshal(rd, c)
	if err != nil {
		return nil, err
	}

	rc := &meshauth.Dest{
		Addr:          "https://" + c.Endpoint + ":443",
		TokenProvider: gcp.TokenProvider,
		//muxID:            "gke_" + p + "_" + c.Location + "_" + c.Name,
	}
	rc.AddTrustPEM(c.MasterAuth.ClusterCaCertificate)

	return rc, err
}

// Get a GCP secrets - used for bootstraping the credentials and provisioning.
//
// Example for creating a secret:
//
//	gcloud secrets create ca \
//	  --data-file <PATH-TO-SECRET-FILE> \
//	  --replication-policy automatic \
//	  --project $PROJECT_ID \
//	  --format json \
//	  --quiet
//
// For MCP/ASM, grant
// service-$PROJECT_NUMBER@gcp-sa-meshdataplane.iam.gserviceaccount.com
// secret manager viewer.
func GetSecret(ctx context.Context, token, p, n, v string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"https://secretmanager.googleapis.com/v1/projects/"+p+"/secrets/"+n+
			"/versions/"+v+":access", nil)
	req.Header.Add("authorization", "Bearer "+token)

	res, err := http.DefaultClient.Do(req)
	rd, err := ioutil.ReadAll(res.Body)
	if res.StatusCode != 200 || err != nil {
		return nil, errors.New(fmt.Sprintf("Error %d %s", res.StatusCode, string(rd)))
	}

	var s struct {
		Payload struct {
			Data []byte
		}
	}
	err = json.Unmarshal(rd, &s)
	if err != nil {
		return nil, err
	}
	return s.Payload.Data, err
}

func (oa *OAuth2Source) GetToken(ctx context.Context, aud string) (string, error) {
	uv := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {oa.RefreshToken},
		"client_id":     {oa.ClientID},
		"client_secret": {oa.ClientSecret},
		"response_type": {"id_token"},
		"audience":      {aud},
	}

	turl := oa.TokenURL
	if turl == "" {
		turl = "https://accounts.google.com/o/oauth2/token" //"https://oauth2.googleapis.com/token"
	}

	req, _ := http.NewRequestWithContext(ctx, "POST", turl, strings.NewReader(uv.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// AuthStyleInParams is used - in header uses basic auth

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	res.Body.Close()
	if err != nil {
		return "", fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}

	var tj tokenJSON
	if err = json.Unmarshal(body, &tj); err != nil {
		return "", fmt.Errorf("oauth2: cannot parse json: %v", err)
	}

	if tj.ErrorCode != "" {
		return "", fmt.Errorf("Error %s %s", tj.ErrorCode, tj.ErrorDescription)
	}

	if aud == "" || tj.IDToken == "" {
		return tj.AccessToken, nil
	}
	return tj.IDToken, nil
}

// From OAuth2 library
// tokenJSON is the struct representing the HTTP response from OAuth2
// providers returning a token or error in JSON form.
// https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
type tokenJSON struct {
	AccessToken  string         `json:"access_token"`
	IDToken      string         `json:"id_token"`
	Scope        string         `json:"scope"`
	TokenType    string         `json:"token_type"`
	RefreshToken string         `json:"refresh_token"`
	ExpiresIn    expirationTime `json:"expires_in"` // at least PayPal returns string, while most return number
	// error fields
	// https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}
type expirationTime int32

func (e *expirationTime) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	var n json.Number
	err := json.Unmarshal(b, &n)
	if err != nil {
		return err
	}
	i, err := n.Int64()
	if err != nil {
		return err
	}
	if i > math.MaxInt32 {
		i = math.MaxInt32
	}
	*e = expirationTime(i)
	return nil
}

// ------------- GCP resources -----------------

// OAuth2Source is the unmarshalled representation of a credentials file.
type OAuth2Source struct {
	Type string `json:"type"` // serviceAccountKey or userCredentialsKey

	// Service Account fields
	ClientEmail  string `json:"client_email"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	TokenURL     string `json:"token_uri"`
	ProjectID    string `json:"project_id"`

	// User Credential fields
	// (These typically come from gcloud auth.)
	ClientSecret string `json:"client_secret"`
	ClientID     string `json:"client_id"`
	RefreshToken string `json:"refresh_token"`
}


// Clusters return the list of GKE clusters.
type Clusters struct {
	Clusters []*Cluster
}

type Cluster struct {
	Name string

	// nodeConfig
	MasterAuth struct {
		ClusterCaCertificate []byte
	}
	Location string

	Endpoint string

	ResourceLabels map[string]string

	// Extras:

	// loggingService, monitoringService
	//Network string "default"
	//Subnetwork string
	ClusterIpv4Cidr  string
	ServicesIpv4Cidr string
	// addonsConfig
	// nodePools

	// For regional clusters - each zone.
	// For zonal - one entry, equal with location
	Locations []string
	// ipAllocationPolicy - clusterIpv4Cider, serviceIpv4Cider...
	// masterAuthorizedNetworksConfig
	// maintenancePolicy
	// autoscaling
	NetworkConfig struct {
		// projects/NAME/global/networks/default
		Network    string
		Subnetwork string
	}
	// releaseChannel
	// workloadIdentityConfig

	// It seems zone and location are the same for zonal clusters.
	//Zone string // ex: us-west1
}

// HubClusters return the list of clusters registered in GKE Hub.
type HubClusters struct {
	Resources []HubCluster
}

type HubCluster struct {
	// Full name - projects/wlhe-cr/locations/global/memberships/asm-cr
	//Name     string
	Endpoint *struct {
		GkeCluster *struct {
			// //container.googleapis.com/projects/wlhe-cr/locations/us-central1-c/clusters/asm-cr
			ResourceLink string
		}
		// kubernetesMetadata: vcpuCount, nodeCount, api version
	}
	State *struct {
		// READY
		Code string
	}

	Authority struct {
		Issuer               string `json:"issuer"`
		WorkloadIdentityPool string `json:"workloadIdentityPool"`
		IdentityProvider     string `json:"identityProvider"`
	} `json:"authority"`

	// Membership labels - different from GKE labels
	Labels map[string]string
}

// GCP has a slightly different concept for 'long operations'.
// - result is the same for all
// - there is a 'wait'
// - result may indicate completion (no need to wait)
// - list, delete supported
//
// AIP-151
//
// longrunning.google.com/v1/
// - List, Get, Delete
// - Wait - but only as gRPC
type Operation struct {

}
