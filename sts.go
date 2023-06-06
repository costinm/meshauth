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
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

// From nodeagent/plugin/providers/google/stsclient
// In Istio, the code is used if "GoogleCA" is set as CA_PROVIDER or CA_ADDR has the right prefix
var (
	// secureTokenEndpoint is the Endpoint the STS client calls to.
	secureTokenEndpoint = "https://sts.googleapis.com/v1/token"

	gcpScope = "https://www.googleapis.com/auth/cloud-platform"

	// urlEncodedForm is the encoding type specified in a STS request.
	urlEncodedForm = "application/x-www-form-urlencoded"
)

// error code sent in a STS error response. A full list of error code is
// defined in https://tools.ietf.org/html/rfc6749#section-5.2.
const (
	// If the request itself is not valid or if either the "subject_token" or
	// "actor_token" are invalid or unacceptable, the STS server must set
	// error code to "invalid_request".
	invalidRequest = "invalid_request"
	// If the authorization server is unwilling or unable to issue a token, the
	// STS server should set error code to "invalid_target".
	invalidTarget = "invalid_target"
)

// STSAuthConfig contains the settings for getting tokens using K8S or other federated tokens.
// Common usage is with a GKE cluster, with either mounted or JWT tokens from TokenRequest.
//
// The mounted tokens MUST use PROJECT_ID.svc.id.goog as audience.
type STSAuthConfig struct {
	// TokenSource returns K8S or 'federation enrolled IDP' tokens with a given audience.
	// Will be called with the 'TrustDomain' as audience for GCP.
	// Typivally a FileTokenSource for the mounted K8S token or use K8S TokenRequest.
	TokenSource TokenSource

	// TrustDomain to use - typically based on fleet_project_name.svc.id.goog
	// Will be used in the identitynamespace param as well as 'audience' in TokenRequest calls.
	//
	// This is currently required.
	TrustDomain string

	// GKE Dest address.
	// https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s
	// It is also the iss field in the token.
	//
	// By default, it will be populated the first time a token is requested.
	ClusterAddress string

	// Endpoint for the STS exchange - takes a IDP JWT and gets back a federated access token.
	// If empty, defaults to google: "https://sts.googleapis.com/v1/token"
	STSEndpoint string

	// Scope to use in the STS exchange.
	// Defaults to google: "https://www.googleapis.com/auth/cloud-platform"
	Scope string
}

// STS provides token exchanges. Implements grpc and golang.org/x/oauth2.TokenSource
// The source of trust is the K8S or other IDP token with TrustDomain audience, it is exchanged with
// access or WorkloadID tokens.
//
// See https://cloud.google.com/iam/docs/reference/sts/rest
// https://www.rfc-editor.org/rfc/rfc6749 - basic oauth2
// https://www.rfc-editor.org/rfc/rfc8693.html
// https://www.ietf.org/archive/id/draft-richer-oauth-json-request-00.html
type STS struct {
	httpClient *http.Client
	cfg        *STSAuthConfig
}

func NewSTS(kr *STSAuthConfig) *STS {
	if kr.Scope == "" {
		kr.Scope = gcpScope
	}
	if kr.STSEndpoint == "" {
		kr.STSEndpoint = secureTokenEndpoint
	}

	return &STS{
		cfg:        kr,
		httpClient: http.DefaultClient,
	}
}

// NewFederatedTokenSource returns federated tokens - google access tokens
// associated with the federated (k8s) identity. Can be used in some but not
// all APIs - in particular MeshCA requires this token.
//
// https://cloud.google.com/iam/docs/reference/sts/rest/v1/TopLevel/token
func NewFederatedTokenSource(kr *STSAuthConfig) *STS {
	if kr.Scope == "" {
		kr.Scope = gcpScope
	}
	if kr.STSEndpoint == "" {
		kr.STSEndpoint = secureTokenEndpoint
	}

	return &STS{
		cfg: kr,

		httpClient: http.DefaultClient,
	}
}

func md(t string) map[string]string {
	res := map[string]string{
		"authorization": "Bearer " + t,
	}
	return res
}

// GetRequestMetadata implements credentials.PerRPCCredentials
// This can be used for both WorkloadID tokens or access tokens - if the 'aud' containts googleapis.com, access tokens are returned.
func (s *STS) GetRequestMetadata(ctx context.Context, aud ...string) (map[string]string, error) {
	ta := ""
	if len(aud) > 0 {
		ta = aud[0]
	}
	if len(aud) > 1 {
		return nil, singleAudienceError
	}
	t, err := s.GetToken(ctx, ta)
	if err != nil {
		return nil, err
	}
	return md(t), nil
}

func (s *STS) GetToken(ctx context.Context, aud string) (string, error) {
	// Get the K8S-signed JWT with audience based on the project-id. This is the required input to get access tokens.
	kt, err := s.cfg.TokenSource.GetToken(ctx, s.cfg.TrustDomain)
	if err != nil {
		return "", err
	}

	// TODO: read from file as well - if TokenSource is not set for example.

	// Federated token - a google access token equivalent with the k8s JWT, using STS
	ft, err := s.TokenFederated(ctx, kt)
	if err != nil {
		return "", err
	}

	return ft, nil
}

func (s *STS) RequireTransportSecurity() bool {
	return false
}

// TokenFederated exchanges the K8S JWT with a federated token - an google access token representing
// the K8S identity (and not a regular GSA!).
//
// (formerly called ExchangeToken)
func (s *STS) TokenFederated(ctx context.Context, k8sSAjwt string) (string, error) {
	if s.cfg.ClusterAddress == "" {
		// First time - construct it from the K8S token
		j := DecodeJWT(k8sSAjwt)
		s.cfg.ClusterAddress = j.Iss
	}
	// Encodes trustDomain, projectid, clustername, location
	stsAud := s.constructAudience()

	jsonStr, err := s.constructFederatedTokenRequest(stsAud, k8sSAjwt)
	if err != nil {
		return "", fmt.Errorf("failed to marshal federated token request: %v", err)
	}

	req, err := http.NewRequest("POST", s.cfg.STSEndpoint, bytes.NewBuffer(jsonStr))
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
	respData := &federatedTokenResponse{}
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

type federatedTokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"` // Expiration time in seconds
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
func (s *STS) constructAudience() string {
	return fmt.Sprintf("identitynamespace:%s:%s", s.cfg.TrustDomain, s.cfg.ClusterAddress)
}

var (
	// tokenExchangeGrantType is the required value for "grant_type" parameter in a STS request.
	tokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

	// subjectTokenTypeJWT is the required token type in a STS request.
	subjectTokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"

	accessTokenType = "urn:ietf:params:oauth:token-type:access_token"
)

// from security/security.go

// stsRequestParameters stores all STS request attributes defined in
// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-16#section-2.1
type stsRequestParameters struct {
	// REQUIRED. The value "urn:ietf:params:oauth:grant-type:token- exchange"
	// indicates that a token exchange is being performed.
	GrantType string `json:"grantType"`
	// REQUIRED. An identifier, that indicates the type of the security token in
	// the "subject_token" parameter.
	SubjectTokenType string `json:"subjectTokenType"`
	// REQUIRED. A security token that represents the identity of the party on
	// behalf of whom the request is being made.
	SubjectToken string `json:"subjectToken"`

	// OPTIONAL. An identifier, for the type of the requested security token.
	RequestedTokenType string `json:"requestedTokenType"`

	// OPTIONAL. The logical name of the target service where the client intends
	// to use the requested security token.
	Audience string `json:"audience"`
	// OPTIONAL. A list of space-delimited, case-sensitive strings, that allow
	// the client to specify the desired Scope of the requested security token in the
	// context of the service or Resource where the token will be used.
	Scope string `json:"scope"`

	// OPTIONAL. Indicates the location of the target service or resource where
	// the client intends to use the requested security token.
	Resource string
	// OPTIONAL. A security token that represents the identity of the acting party.
	ActorToken string
	// An identifier, that indicates the type of the security token in the
	// "actor_token" parameter.
	ActorTokenType string
}

// fetchFederatedToken exchanges a third-party issued Json Web Token for an OAuth2.0 access token
// which asserts a third-party identity within an identity namespace.
func (s *STS) constructFederatedTokenRequest(aud, jwt string) ([]byte, error) {
	data := fmt.Sprintf("grant_type=urn:ietf:params:oauth:grant-type:token-exchange"+
		"&subject_token_type=urn:ietf:params:oauth:token-type:jwt&"+
		"requestedTokenType=urn:ietf:params:oauth:token-type:access_token"+
		"&audience=%s&subject_token=%s",
		url.QueryEscape(aud), url.QueryEscape(jwt))
	if s.cfg.Scope != "" {
		data = data + "&scope=" + url.QueryEscape(s.cfg.Scope)
	}
	return []byte(data), nil
}

// unmarshallTokenRequest validates a STS request, and extracts STS parameters from the request.
func (s *STS) unmarshallTokenRequest(req *http.Request) (*stsRequestParameters, error) {
	reqParam := &stsRequestParameters{}
	if req == nil {
		return reqParam, errors.New("request is nil")
	}

	//if stsServerLog.DebugEnabled() {
	//	reqDump, _ := httputil.DumpRequest(req, true)
	//	stsServerLog.Debugf("Received STS request: %s", string(reqDump))
	//}
	if req.Method != "POST" {
		return reqParam, fmt.Errorf("request method is invalid, should be POST but get %s", req.Method)
	}

	// Envoy seems to be using url encoded form.
	// Google uses json
	encoding := req.Header.Get("Content-Type")
	if encoding == "application/json" {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return reqParam, err
		}
		err = json.Unmarshal(body, &reqParam)
		if err != nil {
			return reqParam, err
		}
		return reqParam, nil
	}

	if encoding != urlEncodedForm {
		return reqParam, fmt.Errorf("request content type is invalid, should be %s but get %s", urlEncodedForm,
			req.Header.Get("Content-type"))
	}

	if parseErr := req.ParseForm(); parseErr != nil {
		return reqParam, fmt.Errorf("failed to parse query from STS request: %v", parseErr)
	}
	if req.PostForm.Get("grant_type") != tokenExchangeGrantType {
		return reqParam, fmt.Errorf("request query grant_type is invalid, should be %s but get %s",
			tokenExchangeGrantType, req.PostForm.Get("grant_type"))
	}
	// Only a JWT token is accepted.
	if req.PostForm.Get("subject_token") == "" {
		return reqParam, errors.New("subject_token is empty")
	}
	if req.PostForm.Get("subject_token_type") != subjectTokenTypeJWT {
		return reqParam, fmt.Errorf("subject_token_type is invalid, should be %s but get %s",
			subjectTokenTypeJWT, req.PostForm.Get("subject_token_type"))
	}
	reqParam.GrantType = req.PostForm.Get("grant_type")
	reqParam.Resource = req.PostForm.Get("resource")
	reqParam.Audience = req.PostForm.Get("audience")
	reqParam.Scope = req.PostForm.Get("scope")
	reqParam.RequestedTokenType = req.PostForm.Get("requested_token_type")
	reqParam.SubjectToken = req.PostForm.Get("subject_token")
	reqParam.SubjectTokenType = req.PostForm.Get("subject_token_type")
	reqParam.ActorToken = req.PostForm.Get("actor_token")
	reqParam.ActorTokenType = req.PostForm.Get("actor_token_type")
	return reqParam, nil
}

// From stsservice/sts.go

// stsResponseParameters stores all attributes sent as JSON in a successful STS
// response. These attributes are defined in
// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-16#section-2.2.1
type stsResponseParameters struct {
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

// ServeStsRequests handles STS requests and sends exchanged token in responses.
// RFC8693 - token exchange
//
// This is intended for localhost use with Envoy - it matches the protocol used by envoy.
// Envoy does send a JWT loaded from a file - this is ignored since we trust localhost in
// sidecar cases.
//
// # It can also be used as a service, with proper Authz prior to
//
// ex. for GCP: https://cloud.google.com/iam/docs/reference/sts/rest/v1beta/TopLevel/token
// https://cloud.google.com/iam/docs/reference/credentials/rest
//
// Should be mapped to /v1/token (but other paths are possible)
func (s *STS) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	reqParam, validationError := s.unmarshallTokenRequest(req)
	if validationError != nil {
		// If request is invalid, the error code must be "invalid_request".
		// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-16#section-2.2.2.
		s.sendErrorResponse(w, invalidRequest, validationError)
		return
	}

	ctx := context.WithValue(req.Context(), "SUBJECT_TOKEN", reqParam.SubjectToken)
	at, err := s.cfg.TokenSource.GetToken(ctx, reqParam.Audience)
	if err != nil {
		s.sendErrorResponse(w, invalidTarget, err)
		return
	}
	if err != nil {
		log.Printf("token manager fails to generate token: %v", err)
		// If the authorization server is unable to issue a token, the "invalid_target" error code
		// should be used in the error response.
		// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-16#section-2.2.2.
		s.sendErrorResponse(w, invalidTarget, err)
		return
	}
	s.sendSuccessfulResponse(w, s.generateSTSRespInner(at))
}

func (p *STS) generateSTSRespInner(token string) []byte {
	//exp, err := time.Parse(time.RFC3339Nano, atResp.ExpireTime)
	// Default token life time is 3600 seconds
	var expireInSec int64 = 3600
	//if err == nil {
	//	expireInSec = int64(time.Until(exp).Seconds())
	//}
	stsRespParam := stsResponseParameters{
		AccessToken:     token,
		IssuedTokenType: accessTokenType,
		TokenType:       "Bearer",
		ExpiresIn:       expireInSec,
	}
	statusJSON, _ := json.MarshalIndent(stsRespParam, "", " ")
	return statusJSON
}

// stsErrorResponse stores all Error parameters sent as JSON in a STS Error response.
// The Error parameters are defined in
// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-16#section-2.2.2.
type stsErrorResponse struct {
	// REQUIRED. A single ASCII Error code.
	Error string `json:"error"`
	// OPTIONAL. Human-readable ASCII [USASCII] text providing additional information.
	ErrorDescription string `json:"error_description"`
	// OPTIONAL. A URI identifying a human-readable web page with information
	// about the Error.
	ErrorURI string `json:"error_uri"`
}

// sendErrorResponse takes error type and error details, generates an error response and sends out.
func (s *STS) sendErrorResponse(w http.ResponseWriter, errorType string, errDetail error) {
	w.Header().Add("Content-Type", "application/json")
	if errorType == invalidRequest {
		w.WriteHeader(http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}
	errResp := stsErrorResponse{
		Error:            errorType,
		ErrorDescription: errDetail.Error(),
	}
	if errRespJSON, err := json.MarshalIndent(errResp, "", "  "); err == nil {
		if _, err := w.Write(errRespJSON); err != nil {
			return
		}
	} else {
		log.Printf("failure in marshaling error response (%v) into JSON: %v", errResp, err)
	}
}

// sendSuccessfulResponse takes token data and generates a successful STS response, and sends out the STS response.
func (s *STS) sendSuccessfulResponse(w http.ResponseWriter, tokenData []byte) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(tokenData); err != nil {
		log.Printf("failure in sending STS success response: %v", err)
		return
	}
}

// ------------ Helpers around TokenSource

type PerRPCCredentialsFromTokenSource struct {
	TokenSource
}

func (s *PerRPCCredentialsFromTokenSource) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	t, err := s.GetToken(ctx, uri[0])
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"authorization": "Bearer: " + t,
	}, nil
}

func (s *PerRPCCredentialsFromTokenSource) RequireTransportSecurity() bool { return false }

type StaticTokenSource struct {
	Token     string
	TokenFile string
}

func (s *StaticTokenSource) GetToken(context.Context, string) (string, error) {
	if s.Token != "" {
		return s.Token, nil
	}
	if s.TokenFile != "" {
		tfb, err := ioutil.ReadFile(s.TokenFile)
		if err != nil {
			return "", err
		}
		// TODO: get expiration, cache
		return string(tfb), nil
	}
	return "", nil
}

func (s *StaticTokenSource) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	t, err := s.GetToken(ctx, uri[0])
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"authorization": "Bearer: " + t,
	}, nil
}

func (s *StaticTokenSource) RequireTransportSecurity() bool { return false }
