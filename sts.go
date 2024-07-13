// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package meshauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// STS client for token exchange.
// Typical usage is to use a K8S token with a special audience, and exchange it for a google tokens.

// The STS protocol is standard - this file has defaults for Google URLs.
// Initially based on Istio nodeagent/plugin/providers/google/stsclient
// In Istio, the code was used if "GoogleCA" is set as CA_PROVIDER or CA_ADDR has the right prefix


var (
	// secureTokenEndpoint is the Endpoint the STS client calls to.
	secureTokenEndpoint = "https://sts.googleapis.com/v1/token"

	GCP_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

	// urlEncodedForm is the encoding type specified in a STS request.
	urlEncodedForm = "application/x-www-form-urlencoded"
)

// STSAuthConfig contains the settings for getting tokens using K8S or other federated tokens.
// Common usage is with a GKE cluster, with either mounted or JWT tokens from TokenRequest.
//
// The mounted tokens MUST use PROJECT_ID.svc.id.goog as audience.
type STSAuthConfig struct {
	// TokenSource returns 'source' tokens - with special audience that allows
	// them to be exchanged.
	//
	// For GKE - the audience should be PROJECT.svc.id.goog.
	// Can be a file source when running in K8S, if the token is mounted.
	TokenSource TokenSource

	// AudienceSource to use when getting tokens from TokenSource.
	// On GKE: fleet_project_name.svc.id.goog
	//
	// Will be used in the identitynamespace param as well as 'audience' in TokenRequest calls.
	// If missing - can be extracted from the token.
	AudienceSource string

	// GKE Dest address.
	// https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s
	// It is also the iss field in the token.
	//
	// By default, it will be populated the first time a token is requested.
	ClusterAddress string

	// Endpoint for the STS exchange - takes a IDP JWT and gets back a
	// federated access token.
	//
	// If empty, defaults to google: "https://sts.googleapis.com/v1/token"
	STSEndpoint string

	// Scope to use in the STS exchange.
	// Defaults to google: "https://www.googleapis.com/auth/cloud-platform"
	Scope string

	// GSA is a Google service account that allows the federated identity to impersonate it ( use ).
	// If not set, the STS will only return access tokens in GCP.
	// If set, the federated token will be exchanged with an ID or access token.
	//
	// The gsa must grant the KSA (kubernetes service account) or source account
	// permission to act as the GSA.
	//
	//	In ASM, a pre-setup account with permissions to stackdriver and control plane is
	// "service-" + projectNumber + "@gcp-sa-meshdataplane.iam.gserviceaccount.com"
	//
	// REQUIRES for regular service account:
	//
	//	gcloud iam service-accounts add-iam-policy-binding \
	//			--role roles/iam.workloadIdentityUser \
	//			--member "serviceAccount:${CONFIG_PROJECT_ID}.svc.id.goog[${WORKLOAD_NAMESPACE}/default]" \
	//			k8s-${WORKLOAD_NAMESPACE}@${PROJECT_ID}.iam.gserviceaccount.com
	GSA string

	// If true, the TokenSource returns access tokens directly.
	// If false, the TokenSource is K8S-based and used to returns K8S JWTs with
	// AudienceSource, further exchanged to federated access tokens, and if GSA is
	// set to service JWT or access tokens.
	//
	// Federated tokens also require cluster info.
	GCPDelegate bool

}

// STS provides token exchanges (RFC8694).
//
// The secure token is the K8S or other IDP token with a special audience,
// the result is a 'federated access token' for GCP or a regular JWT for other
// token exchange servers.
//
// For GKE and GCP - the special values will be used.
//
// See https://cloud.google.com/iam/docs/reference/sts/rest
// https://www.rfc-editor.org/rfc/rfc6749 - basic oauth2
// https://www.rfc-editor.org/rfc/rfc8693.html
// https://www.ietf.org/archive/id/draft-richer-oauth-json-request-00.html
type STS struct {
	httpClient *http.Client
	cfg        *STSAuthConfig
}

// NewFederatedTokenSource returns federated tokens - google access tokens
// associated with the federated (k8s) identity. Can be used in some but not
// all APIs - in particular MeshCA requires this token.
//
// https://cloud.google.com/iam/docs/reference/sts/rest/v1/TopLevel/token
//
// If GSA is set, will also delegate to a Google account.
func NewFederatedTokenSource(kr *STSAuthConfig) *STS {
	if kr.STSEndpoint == "" {
		kr.STSEndpoint = secureTokenEndpoint
		kr.Scope = GCP_SCOPE
	}

	return &STS{
		cfg:        kr,
		httpClient: http.DefaultClient,
	}
}

// GetToken for STS returns an access token if aud is empty.
func (s *STS) GetToken(ctx context.Context, aud string) (string, error) {
	var federatedAccessToken string
	var err error
	var kt string

	if s.cfg.GCPDelegate {
		// Directly get the access token from the parent - no exchange needed, usually the prent is ADC or MDS.
		// The token may be a federated token on GKE - or an access token on GCP.
		federatedAccessToken, err = s.cfg.TokenSource.GetToken(ctx, "")
		if err != nil {
			return "", err
		}
	} else {
		// Get the K8S-signed JWT with audience based on the project-id. This is the required input to get access tokens.
		kt, err = s.cfg.TokenSource.GetToken(ctx, s.cfg.AudienceSource)
		if err != nil {
			slog.Info("STS failed to get K8S token", "err", err, "fedaud", s.cfg.AudienceSource)
			return "", err
		}

		// Federated token - a google access token equivalent with the k8s JWT, using STS
		federatedAccessToken, err = s.exchangeK8SJWT2FederatedAccessToken(ctx, kt, aud)
		if err != nil {
			slog.Info("STS failed to get fed access token", "err", err, "fedaud", s.cfg.AudienceSource, "aud", aud)
			return "", err
		}
	}
	// TODO: read from file as well - if TokenSource is not set for example.

	if s.cfg.GSA != "" {
		// GCP special config - the token exchange can't delegate, so a 3rd roundtrip is needed
		t, err := s.TokenGSA(ctx, federatedAccessToken, aud)
		if err != nil {
			jwt := DecodeJWT(kt)

			slog.Info("STS failed use fed access token for GSA", "err", err, "fedaud", s.cfg.AudienceSource, "gsa", s.cfg.GSA, "jwt", jwt)

		}
		return t, err
	}

	return federatedAccessToken, nil
}

// TokenFederated exchanges the K8S JWT with a federated token - an google access token representing
// the K8S identity (and not a regular GSA!).
//
// (formerly called ExchangeToken)
func (s *STS) exchangeK8SJWT2FederatedAccessToken(ctx context.Context, subjectToken string, aud string) (string, error) {

	if s.cfg.ClusterAddress == "" {
		// First time - construct it from the K8S token
		j := DecodeJWT(subjectToken)
		if j == nil {
			return "", errors.New("Invalid jwt")
		}
		s.cfg.ClusterAddress = j.Iss
	}

	// GCP: kid=jwt, alt rs256 or es256
	// iss, iat, exp
	// sub
	// aud - in case of GKE the projectid.

	// Encodes trustDomain, projectid, clustername, location
	// This is the google format
	stsAud := s.constructAudience(aud)

	urlEncodedBody, err := s.constructFederatedTokenRequest(stsAud, subjectToken)
	if err != nil {
		return "", fmt.Errorf("failed to marshal federated token request: %v", err)
	}

	req, err := http.NewRequest("POST", s.cfg.STSEndpoint,
		bytes.NewBuffer(urlEncodedBody))
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req = req.WithContext(ctx)

	res, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange failed: %v, (aud: %s, STS endpoint: %s)", err, stsAud, s.cfg.STSEndpoint)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("token exchange read failed: %v, (aud: %s, STS endpoint: %s)", err, stsAud, s.cfg.STSEndpoint)
	}
	respData := &TokenResponse{}
	if err := json.Unmarshal(body, respData); err != nil {
		// Normally the request should json - extremely hard to debug otherwise, not enough info in status/err
		log.Println("Unexpected unmarshal error, response was ", string(body))
		return "", fmt.Errorf("(aud: %s, STS endpoint: %s), failed to unmarshal response data of size %v: %v",
			stsAud, s.cfg.STSEndpoint, len(body), err)
	}

	if respData.AccessToken == "" {
		return "", fmt.Errorf(
			"exchanged empty token (aud: %s, STS endpoint: %s), response: %v", stsAud, s.cfg.STSEndpoint, string(body))
	}

	return respData.AccessToken, nil
}

// provider can be extracted from metadata server, or is set using GKE_ClusterURL
//
// For VMs, it is set as GoogleComputeEngine via CREDENTIAL_IDENTITY_PROVIDER env
// In Istio GKE it is constructed from metadata, on VM it is GKE_CLUSTER_URL or gcp_gke_cluster_url,
// format "https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s" - this also happens to be
// the 'iss' field in the token.
// According to docs, aud can be:
// iam.googleapis.com/projects/<project-number>/locations/global/workloadIdentityPools/<pool-id>/providers/<provider-id>.
// or gcloud URL
// Required when exchanging an external credential for a Google access token.
func (s *STS) constructAudience(aud string) string {
	if s.cfg.STSEndpoint == secureTokenEndpoint {
		// The full resource name of the identity provider; for example:
		//  iam.googleapis.com/projects/<project-number>/locations/global/workloadIdentityPools/<pool-id>/providers/<provider-id> for
		// workload identity pool providers, or
		//  iam.googleapis.com/locations/global/workforcePools/<pool-id>/providers/<provider-id>
		//  for workforce pool providers.
		// Required when exchanging an external credential for a Google access token.

		return fmt.Sprintf("identitynamespace:%s:%s", s.cfg.AudienceSource,
			s.cfg.ClusterAddress)
	} else {
		return aud
	}
}

var (
	// TokenExchangeGrantType is the required value for "grant_type" parameter in a STS request.
	TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

	// SubjectTokenTypeJWT is the required token type in a STS request.
	SubjectTokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"

	AccessTokenType = "urn:ietf:params:oauth:token-type:access_token"
)

// fetchFederatedToken exchanges a third-party issued Json Web Token for an OAuth2.0 access token
// which asserts a third-party identity within an identity namespace.
func (s *STS) constructFederatedTokenRequest(aud, jwt string) ([]byte, error) {
	data := fmt.Sprintf(
		"grant_type=urn:ietf:params:oauth:grant-type:token-exchange"+
			"&subject_token_type=urn:ietf:params:oauth:token-type:jwt"+
			"&requestedTokenType=urn:ietf:params:oauth:token-type:access_token"+
			"&audience=%s"+
			"&subject_token=%s",
		url.QueryEscape(aud), url.QueryEscape(jwt))
	if s.cfg.Scope != "" {
		data = data + "&scope=" + url.QueryEscape(s.cfg.Scope)
	}
	return []byte(data), nil
}

// From stsservice/sts.go

// TokenResponse stores all attributes sent as JSON in a successful STS
// response. These attributes are defined in RFC8693 2.2.1
// Also RFC6749 5.1 and https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-16#section-2.2.1
// Also used by the MDS.
type TokenResponse struct {
	// REQUIRED. The security token issued by the authorization server
	// in response to the token exchange request.
	AccessToken string `json:"access_token"`

	// REQUIRED. An identifier, representation of the issued security token.
	IssuedTokenType string `json:"issued_token_type"`

	// REQUIRED. A case-insensitive value specifying the method of using the access
	// token issued. It provides the client with information about how to utilize the
	// access token to access protected resources.
	TokenType string `json:"token_type"`

	// RECOMMENDED. The validity lifetime, in seconds, of the token issued by the
	// authorization server.
	ExpiresIn int64 `json:"expires_in"`

	// OPTIONAL, if the Scope of the issued security token is identical to the
	// Scope requested by the client; otherwise, REQUIRED.
	Scope string `json:"scope"`

	// OPTIONAL. A refresh token will typically not be issued when the exchange is
	// of one temporary credential (the subject_token) for a different temporary
	// credential (the issued token) for use in some other context.
	RefreshToken string `json:"refresh_token"`
}

// From tokenexchangeplugin.go
type Duration struct {
	// Signed seconds of the span of time. Must be from -315,576,000,000
	// to +315,576,000,000 inclusive. Note: these bounds are computed from:
	// 60 sec/min * 60 min/hr * 24 hr/day * 365.25 days/year * 10000 years
	Seconds int64 `json:"seconds"`
}

//func (ms Duration) MarshalJSON() ([]byte, error) {
//	return json.Marshal(ms.String())
//}
//
//func (ms *Duration) UnmarshalJSON(data []byte) error {
//	var v interface{}
//	if err := json.Unmarshal(data, &v); err != nil {
//		return err
//	}
//	switch value := v.(type) {
//	case float64:
//		*ms = Duration{Duration: time.Duration(value)}
//		return nil
//	case string:
//		var err error
//		s, err := time.ParseDuration(value)
//		if err != nil {
//			return err
//		}
//		*ms = Duration{Duration: s}
//		return nil
//	default:
//		return errors.New("invalid duration")
//	}
//}


// Exchange a federated token equivalent with the k8s JWT with the ASM p4SA.
// TODO: can be used with any GSA, if the permission to call generateAccessToken is granted.
// This is a good way to get access tokens for a GSA using the KSA, similar with TokenRequest in
// the other direction.
//
// May return an WorkloadID token with aud or access token.
//
// https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects/-/serviceAccounts/generateAccessToken
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
func (s *STS) TokenGSA(ctx context.Context, federatedToken string, audience string) (string, error) {
	accessToken := audience == ""  ||
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
				"Failed to get GSA access token from federated access token GSA=%s, response: %v", s.cfg.GSA, string(body))
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
)

// iamServiceAccountGenerate implements the 'generateAccessToken' protocol for google service accounts.
//
// 'sourceToken' is a federated token ( can be another google access token, if the permissions are set).
//
// https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
// https://oauth2.googleapis.com/token - with refresh_token
func (s *STS) iamServiceAccountGenerate(ctx context.Context, sourceToken string, audience string, accessToken bool) (*http.Request, error) {
	gsa := s.cfg.GSA
	endpoint := ""
	var err error
	var jsonQuery []byte
	if accessToken {
		endpoint = fmt.Sprintf(gcpServiceAccountEndpointAccess, gsa)
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
	if Debug {
		reqDump, _ := httputil.DumpRequest(req, true)
		log.Println("Prepared access token request: ", string(reqDump))
	}
	req.Header.Add("Authorization", "Bearer "+sourceToken) // the AccessToken
	return req, nil
}
