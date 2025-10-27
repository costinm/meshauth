package ugcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/costinm/meshauth/pkg/tokens"
)

// IAMServiceAccount is a google 'service account' - managed as part of a project,
// with attached IAM permissions.
//
// It can generate OIDC tokens signed by google.
//
// Regular user accounts (gmail or 'apps' or federated) can't usually get OIDC
// tokens except via OpenID flows. They can get 'access' tokens for google
// services, including the exchange with service account tokens (acting as).
// This is the 'AccessTokenSource'. GKE is a federated source, auto-registered.
//
// With gcloud command, JWTs with audience set to gcloud project
// can be retrieved because the OAuth2 flow is used.
//
// Requires:
//  gcloud iam service-accounts add-iam-policy-binding \
//  SERVICE_ACCOUNT_B-email@project-id.iam.gserviceaccount.com \
//  --member=user:ACCOUNT_A-email@gmail.com \
//  --role=roles/iam.serviceAccountTokenCreator
type IAMServiceAccount struct {
	// The source of the access token - MDS or K8S federated or GAC
	//
	AccessTokenSource tokens.TokenSource

	// The service account.
	GSA string

	httpClient *http.Client
}

// Google-specific OIDC token for the GSA
func (iamServiceAccount *IAMServiceAccount) GetToken(ctx context.Context, aud string) (string, error) {
	at, err := iamServiceAccount.AccessTokenSource.GetToken(ctx, "")
	if err != nil {
		return "", err
	}

	return iamServiceAccount.TokenGSA(ctx, at, aud)
}

// Using a federated or user access token (with proper IAM permissions on the GSA),
// return the OIDC JWT.
//
// If aud is empty or is for googleapis.com - return access token instead.
func (s *IAMServiceAccount) TokenGSA(ctx context.Context, federatedToken string, audience string) (string, error) {
	accessToken := audience == "" ||
			strings.Contains(audience, "googleapis.com")

	req, err := s.iamServiceAccountGenerate(ctx, federatedToken, audience, accessToken)
	if err != nil {
		return "", fmt.Errorf("failed to marshal federated token request: %v", err)
	}
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
				"Failed to get GSA access token from federated access token GSA=%s, response: %v", s.GSA, string(body))
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

type Duration struct {
	// Signed seconds of the span of time. Must be from -315,576,000,000
	// to +315,576,000,000 inclusive. Note: these bounds are computed from:
	// 60 sec/min * 60 min/hr * 24 hr/day * 365.25 days/year * 10000 years
	Seconds int64 `json:"seconds"`
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

var (
	gcpServiceAccountEndpointAccess = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken"
	gcpServiceAccountEndpointJWT    = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken"

	GCP_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

)

// iamServiceAccountGenerate implements the 'generateAccessToken' protocol for google service accounts.
//
// 'sourceToken' is a federated token ( can be another google access token, if the permissions are set).
//
// https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
//
// https://oauth2.googleapis.com/token - with refresh_token
func (s *IAMServiceAccount) iamServiceAccountGenerate(ctx context.Context, sourceToken string, audience string, accessToken bool) (*http.Request, error) {
	gsa := s.GSA
	endpoint := ""
	var err error
	var jsonQuery []byte
	if accessToken {
		endpoint = fmt.Sprintf(gcpServiceAccountEndpointAccess, gsa)
		// Request for access token with a lifetime of 3600 seconds.
		query := accessTokenRequest{
			LifeTime: Duration{Seconds: 3600},
		}
		query.Scope = append(query.Scope, GCP_SCOPE)

		jsonQuery, err = json.Marshal(query)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal query for get access token request: %+v", err)
		}
	} else {
		endpoint = fmt.Sprintf(gcpServiceAccountEndpointJWT, gsa)
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
	//if Debug {
	//	reqDump, _ := httputil.DumpRequest(req, true)
	//	log.Println("Prepared access token request: ", string(reqDump))
	//}
	req.Header.Add("Authorization", "Bearer "+sourceToken) // the AccessToken
	return req, nil
}
