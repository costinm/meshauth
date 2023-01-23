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

// JSON key file types.
const (
	serviceAccountKey  = "service_account"
	userCredentialsKey = "authorized_user"
)

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
	httpClient *http.Client
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
func (gcpa *GCPAuth) LoadManaged() {
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
// Example of an access token request:
// POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/
// service-<GCP project number>@gcp-sa-meshdataplane.iam.gserviceaccount.com:generateAccessToken
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
// The p4sa is auto-setup for all authenticated users.
func (s *GCPAuth) TokenGSA(ctx context.Context, federatedToken string, audience string) (string, error) {
	accessToken := audience == "" || s.cfg.UseAccessToken ||
		strings.Contains(audience, "googleapis.com")

	req, err := s.constructGenerateAccessTokenRequest(federatedToken, audience, accessToken)
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

func (s *GCPAuth) constructGenerateAccessTokenRequest(fResp string, audience string, accessToken bool) (*http.Request, error) {
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
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonQuery))
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

type accessTokenRequest struct {
	Name      string   `json:"name"` // nolint: structcheck, unused
	Delegates []string `json:"delegates"`
	Scope     []string `json:"scope"`
	LifeTime  Duration `json:"lifetime"` // nolint: structcheck, unused
}

type idTokenRequest struct {
	Audience     string   `json:"audience"` // nolint: structcheck, unused
	Delegates    []string `json:"delegates"`
	IncludeEmail bool     `json:"includeEmail"`
}

type accessTokenResponse struct {
	AccessToken string `json:"accessToken"`
	ExpireTime  string `json:"expireTime"`
}

type idTokenResponse struct {
	Token string `json:"token"`
}
