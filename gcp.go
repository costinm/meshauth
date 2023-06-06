//go:build !NO_VENDOR
// +build !NO_VENDOR

package meshauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
)

// Dependency-less GCP integration

// See golang.org/x/oauth2/google

// Extracted minimal resources to reduce deps.

// Subset of the generated GCP config - to avoid a dependency and bloat.
// This include just what we need for bootstraping from GKE, Hub or secret store.
//
// There are few mechanisms to bootstrap GCP identity:
// 1. MDS - this is likely best for VM and CR, but on GKE requires annotating the KSA.
//    It does return a federated access token otherwise - but no ID tokens.
// 2. Downloaded service account key, with a private key to sign JWTs
// 3. Gcloud config - returns a user account, can get access tokens and exchange for a GSA
// 4. Federated - also 'best', starting with a K8S or any other OIDC provider.
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

// GCPAccessTokenSource creates GCP access tokens for the given GSA. If empty, ASM default service account
// will be used as long as PROJECT_NUMBER is set.
func (def *K8SCluster) GCPAccessTokenSource(gsa string) (*GCPAuth, error) {
	if gsa == "" {
		// Init a GCP token source - using K8S provider and exchange.
		// TODO: if we already have a GCP GSA, we can use that directly.
		projectNumber := def.GetEnv("PROJECT_NUMBER", "")
		if projectNumber == "" {
			return nil, errors.New("Missing PROJECT_NUMBER")
		}
		gsa = "service-" + projectNumber + "@gcp-sa-meshdataplane.iam.gserviceaccount.com"
	}

	// This returns JWT tokens for k8s
	//audTokenS := k8s.K8sTokenSource{Dest: k8sdefault, Namespace: hb.Namespace,
	//	KSA: hb.ServiceAccount}
	fedS := NewFederatedTokenSource(&STSAuthConfig{
		TrustDomain: def.ProjectID + ".svc.id.goog",
		TokenSource: &K8sTokenSource{
			Cluster:   def,
			Namespace: def.Namespace,
			KSA:       def.ServiceAccount},
	})

	audTokenS := NewGCPTokenSource(&GCPAuthConfig{
		TokenSource: fedS,
		GSA:         gsa,
		TrustDomain: def.ProjectID + ".svc.id.goog",
	})
	return audTokenS, nil
}

// STSAuthConfig contains the settings for getting tokens using K8S or federated tokens.
type GCPAuthConfig struct {
	// TokenSource returns K8S or 'federation enrolled IDP' tokens with a given audience.
	// Will be called with the 'TrustDomain' as audience for GCP.
	TokenSource TokenSource

	// Used to construct the default GSA for ASM
	//  "service-" + kr.ProjectNumber + "@gcp-sa-meshdataplane.iam.gserviceaccount.com"
	ProjectNumber string

	// Google service account to impersonate and return tokens for.
	// The KSA returned from K8S must have the IAM permissions
	GSA string

	// TrustDomain to use - typically based on fleet_project_name.svc.id.goog
	TrustDomain string

	// Endpoint for the STS exchange - takes a IDP JWT and gets back a federated access token.
	// For google: "https://sts.googleapis.com/v1/token"
	STSEndpoint string

	// Endpoint gets a federated access token (or any other access token with permissions),
	// returns an access token for the target service account
	// For google:  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken"
	AccessTokenEndpoint string

	// Similar to AccessTokenEndpoint, but returns ID tokens (JWTs with audience)
	// For google:  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken"
	IDTokenEndpoint string

	// Scope to use in the STS exchange.
	// For google: "https://www.googleapis.com/auth/cloud-platform"
	Scope string

	// UseAccessToken will force returning a GSA access token, regardless of audience.
	// Only valid for FederatedTokenSource, or if a GSA is provided.
	UseAccessToken bool
}

// STS provides token exchanges. Implements grpc and golang.org/x/oauth2.TokenSource
// The source of trust is the K8S or other IDP token with TrustDomain audience, it is exchanged with
// access or WorkloadID tokens.
type GCPAuth struct {
	httpClient HttpClient
	cfg        *GCPAuthConfig
}

var (
	gcpServiceAccountEndpointAccess = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken"
	gcpServiceAccountEndpointJWT    = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken"
)

// NewGSATokenSource returns a oauth2.TokenSource and
// grpc credentials.PerRPCCredentials implmentation, returning access
// or ID tokens for a Google Service Account.
//
// The TokenSource provided in the GCPAuthConfig should return GCP access tokens,
// including federated (from STS), for a GSA with permissions for the target 'gsa'.
//
// If the gsa is empty, the ASM mesh P4SA will be used instead. This is
// suitable for connecting to stackdriver and out-of-cluster managed Istiod.
// Otherwise, the gsa must grant the KSA (kubernetes service account)
// permission to act as the GSA.
func NewGCPTokenSource(kr *GCPAuthConfig) *GCPAuth {
	if kr == nil {
		kr = &GCPAuthConfig{}
	}
	sts := &GCPAuth{
		cfg: kr,
	}
	if kr.Scope == "" {
		kr.Scope = gcpScope
	}
	sts.httpClient = http.DefaultClient

	if kr.GSA == "" {
		// use the mesh default SA
		// If not set, default to ASM default SA.
		// This has stackdriver, TD, MCP permissions - and is available to all
		// workloads. Only works for ASM clusters.
		kr.GSA = "service-" + kr.ProjectNumber + "@gcp-sa-meshdataplane.iam.gserviceaccount.com"
	}
	if kr.IDTokenEndpoint == "" {
		kr.IDTokenEndpoint = gcpServiceAccountEndpointJWT
	}
	if kr.AccessTokenEndpoint == "" {
		kr.AccessTokenEndpoint = gcpServiceAccountEndpointAccess
	}
	//sts.UseAccessToken = true
	return sts
}

// WIP - if GOOGLE_APPLICATION_CREDENTIALS is present, load it
// and use it as a source of access tokens instead of k8s.
// Same for MDS
func (gcpa *GCPAuth) loadJWTCredentials() {
	adc := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if adc != "" {
		b, err := ioutil.ReadFile(adc)
		if err == nil {
			cf := &credentialsFile{}
			err = json.Unmarshal(b, cf)
			// TODO: use refresh token and token_uri ("https://accounts.google.com/o/oauth2/token")
		}
	}
}

// GetRequestMetadata implements credentials.PerRPCCredentials
// This can be used for both WorkloadID tokens or access tokens - if the 'aud' containts googleapis.com, access tokens are returned.
func (s *GCPAuth) GetRequestMetadata(ctx context.Context, aud ...string) (map[string]string, error) {
	ta := ""
	if len(aud) > 0 {
		ta = aud[0]
	}
	if len(aud) > 1 {
		return nil, errors.New("Single audience supporte")
	}
	t, err := s.GetToken(ctx, ta)
	if err != nil {
		return nil, err
	}
	return md(t), nil
}

func (s *GCPAuth) GetToken(ctx context.Context, aud string) (string, error) {
	// Get the K8S-signed JWT with audience based on the project-id. This is the required input to get access tokens.
	ft, err := s.cfg.TokenSource.GetToken(ctx, s.cfg.TrustDomain)
	if err != nil {
		return "", err
	}

	// TODO: read from file as well - if TokenSource is not set for example.

	if s.cfg.GSA == "" {
		return ft, nil
	}

	token, err := s.TokenGSA(ctx, ft, aud)
	return token, err
}

func (s *GCPAuth) RequireTransportSecurity() bool {
	return false
}

// Exchange a federated token equivalent with the k8s JWT with the ASM p4SA.
// TODO: can be used with any GSA, if the permission to call generateAccessToken is granted.
// This is a good way to get access tokens for a GSA using the KSA, similar with TokenRequest in
// the other direction.
//
// May return an WorkloadID token with aud or access token.
//
// https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
//
// constructFederatedTokenRequest returns an HTTP request for access token.
//
// Example of an access token request:
//
// POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/service-<GCP project number>@gcp-sa-meshdataplane.iam.gserviceaccount.com:generateAccessToken
// Content-Type: application/json
// Authorization: Bearer <federated token>
//
//	{
//	 "Delegates": [],
//	 "Scope": [
//	     https://www.googleapis.com/auth/cloud-platform
//	 ],
//	}
//
// This requires permission to impersonate:
//
//	gcloud iam service-accounts add-iam-policy-binding \
//	 GSA_NAME@GSA_PROJECT_ID.iam.gserviceaccount.com \
//	 --role=roles/iam.workloadIdentityUser \
//	 --member="serviceAccount:WORKLOAD_IDENTITY_POOL[K8S_NAMESPACE/KSA_NAME]"
//
// This can also be used with user access tokens, if user has
//
//	roles/iam.serviceAccountTokenCreator (for iam.serviceAccounts.getOpenIdToken)
//
// The p4sa is auto-setup for all authenticated users in ASM.
func (s *GCPAuth) TokenGSA(ctx context.Context, federatedToken string, audience string) (string, error) {
	accessToken := audience == "" || s.cfg.UseAccessToken ||
		strings.Contains(audience, "googleapis.com")

	req, err := s.constructGenerateAccessTokenRequest(ctx, federatedToken, audience, accessToken)
	if err != nil {
		return "", fmt.Errorf("failed to marshal federated token request: %v", err)
	}
	req = req.WithContext(ctx)
	res, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("token exchange failed: %v", err)
	}

	// Create an access token
	if accessToken {
		respData := &accessTokenResponse{}

		if err := json.Unmarshal(body, respData); err != nil {
			// Normally the request should json - extremely hard to debug otherwise, not enough info in status/err
			log.Println("Unexpected unmarshal error, response was ", string(body))
			return "", fmt.Errorf("failed to unmarshal response data of size %v: %v",
				len(body), err)
		}

		if respData.AccessToken == "" {
			return "", fmt.Errorf(
				"exchanged empty token, response: %v", string(body))
		}

		return respData.AccessToken, nil
	}

	// Return an WorkloadID token for the GSA
	respData := &idTokenResponse{}

	if err := json.Unmarshal(body, respData); err != nil {
		// Normally the request should json - extremely hard to debug otherwise, not enough info in status/err
		log.Println("Unexpected unmarshal error, response was ", string(body))
		return "", fmt.Errorf("failed to unmarshal response data of size %v: %v",
			len(body), err)
	}

	if respData.Token == "" {
		return "", fmt.Errorf(
			"exchanged empty token, response: %v", string(body))
	}

	return respData.Token, nil
}

// Equivalent config using shell:
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

// GKE2RestCluster gets all the clusters for a project, and returns Cluster object.
func (gcp *GCPAuth) GKEClusters(ctx context.Context, token string, p string) ([]*Dest, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://container.googleapis.com/v1/projects/"+p+"/locations/-/clusters", nil)

	if token != "" {
		req.Header.Add("authorization", "Bearer "+token)
	}

	res, err := gcp.httpClient.Do(req)
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
	if Debug {
		log.Println(string(rd))
	}

	cl := &Clusters{}
	err = json.Unmarshal(rd, cl)
	if err != nil {
		return nil, err
	}
	rcl := []*Dest{}

	for _, c := range cl.Clusters {
		rc := &Dest{
			BaseAddr:    "https://" + c.Endpoint + ":443",
			TokenSource: gcp,
			//ID:            "gke_" + p + "_" + c.Location + "_" + c.Name,
		}
		rc.AddCACertPEM(c.MasterAuth.ClusterCaCertificate)

		rcl = append(rcl, rc)
	}

	return rcl, err
}

func (gcp *GCPAuth) HubClusters(ctx context.Context, token string, p string) ([]*Dest, error) {
	req, _ := http.NewRequest("GET",
		"https://gkehub.googleapis.com/v1/projects/"+p+"/locations/-/memberships", nil)
	req = req.WithContext(ctx)
	if token != "" {
		req.Header.Add("authorization", "Bearer "+token)
	}

	res, err := gcp.httpClient.Do(req)
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
	if Debug {
		log.Println(string(rd))
	}

	cl := &HubClusters{}
	err = json.Unmarshal(rd, cl)
	if err != nil {
		return nil, err
	}
	rcl := []*Dest{}

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

// GetCluster returns a cluster config using the GKE API. Path must follow GKE API spec: /projects/P/locations/L/l
func (gcp *GCPAuth) GKECluster(ctx context.Context, token string, path string) (*Dest, error) {
	req, _ := http.NewRequest("GET", "https://container.googleapis.com/v1"+path, nil)
	req = req.WithContext(ctx)
	if token != "" {
		req.Header.Add("authorization", "Bearer "+token)
	}

	res, err := gcp.httpClient.Do(req)
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
	if Debug {
		log.Println(string(rd))
	}

	c := &Cluster{}
	err = json.Unmarshal(rd, c)
	if err != nil {
		return nil, err
	}

	rc := &Dest{
		BaseAddr:    "https://" + c.Endpoint + ":443",
		TokenSource: gcp,
		//ID:            "gke_" + p + "_" + c.Location + "_" + c.Name,
	}
	rc.AddCACertPEM(c.MasterAuth.ClusterCaCertificate)

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
func (gcp *GCPAuth) GetSecret(ctx context.Context, token, p, n, v string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"https://secretmanager.googleapis.com/v1/projects/"+p+"/secrets/"+n+
			"/versions/"+v+":access", nil)
	req.Header.Add("authorization", "Bearer "+token)

	res, err := gcp.httpClient.Do(req)
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

// https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
func (s *GCPAuth) constructGenerateAccessTokenRequest(ctx context.Context, fResp string, audience string, accessToken bool) (*http.Request, error) {
	gsa := s.cfg.GSA
	endpoint := ""
	var err error
	var jsonQuery []byte
	if accessToken {
		endpoint = fmt.Sprintf(s.cfg.AccessTokenEndpoint, gsa)
		// Request for access token with a lifetime of 3600 seconds.
		query := accessTokenRequest{
			LifeTime: Duration{Seconds: 3600},
		}
		query.Scope = append(query.Scope, s.cfg.Scope)

		jsonQuery, err = json.Marshal(query)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal query for get access token request: %+v", err)
		}
	} else {
		endpoint = fmt.Sprintf(s.cfg.IDTokenEndpoint, gsa)
		// Request for access token with a lifetime of 3600 seconds.
		query := idTokenRequest{
			IncludeEmail: true,
			Audience:     audience,
		}

		jsonQuery, err = json.Marshal(query)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal query for get access token request: %+v", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonQuery))
	if err != nil {
		return nil, fmt.Errorf("failed to create get access token request: %+v", err)
	}
	req.Header.Add("Content-Type", "application/json")
	if Debug {
		reqDump, _ := httputil.DumpRequest(req, true)
		log.Println("Prepared access token request: ", string(reqDump))
	}
	req.Header.Add("Authorization", "Bearer "+fResp) // the AccessToken
	return req, nil
}

// ------------- GCP resources -----------------
// Extracted minimal resources to reduce deps.
// This is a subset - rest of fields not used and ignored.
// The API is expected to remain backward compatible.
// This includes just what we need for bootstraping from GKE, Hub or secret store.

type accessTokenRequest struct {
	Name      string   `json:"name"` // nolint: structcheck, unused
	Delegates []string `json:"delegates,omitempty"`
	Scope     []string `json:"scope"`
	LifeTime  Duration `json:"lifetime"` // nolint: structcheck, unused
}

type idTokenRequest struct {
	Audience     string   `json:"audience"` // nolint: structcheck, unused
	Delegates    []string `json:"delegates,omitempty"`
	IncludeEmail bool     `json:"includeEmail"`
}

type accessTokenResponse struct {
	AccessToken string `json:"accessToken"`
	ExpireTime  string `json:"expireTime"`
}

type idTokenResponse struct {
	Token string `json:"token"`
}

// credentialsFile is the unmarshalled representation of a credentials file.
type credentialsFile struct {
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
