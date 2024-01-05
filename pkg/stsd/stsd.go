package stsd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/costinm/meshauth"
)

// TokenExchangeD is an OAuth2 token exchange server, RFC8694 -(extending RFC6749
// which covers OAuth2)
//
// This is also called "Secure Token Service" - the source of trust is a
// "security token" - a K8S JWT with a special audience or a JWT from a
// different provider.
//
// It currently accepts grant_type 'token-exchange', with a 'jwt' subject token.
//
// It can returns access_token and JWT tokens.
type TokenExchangeD struct {
	Authn    *meshauth.Authn
	Generate func(context.Context, *meshauth.JWT, string) (string, error)
}

// from security/security.go

// TokenExchangeRequest stores all STS request attributes defined in
// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-16#section-2.1
type TokenExchangeRequest struct {
	// REQUIRED. The value "urn:ietf:params:oauth:grant-type:token-exchange"
	// indicates that a token exchange is being performed.
	//
	// Other values: refresh_token, authorization_code, client_credentials
	//
	GrantType string `json:"grantType"`

	// REQUIRED. A security token that represents the identity of the party on
	// behalf of whom the request is being made.
	SubjectToken string `json:"subjectToken"`

	// REQUIRED. An identifier, that indicates the type of the security token in
	// the "subject_token" parameter.
	SubjectTokenType string `json:"subjectTokenType"`

	// OPTIONAL. An identifier, for the type of the requested security token.
	RequestedTokenType string `json:"requestedTokenType"`

	// OPTIONAL in RFC, required by GCP.
	// The logical name of the target service where the client intends
	// to use the requested security token.
	Audience string `json:"audience"`

	// OPTIONAL, required in GCP. A list of space-delimited, case-sensitive strings, that allow
	// the client to specify the desired Scope of the requested security token in the
	// context of the service or Resource where the token will be used.
	Scope string `json:"scope"`

	// OPTIONAL. Indicates the location of the target service or resource where
	// the client intends to use the requested security token.
	Resource string `json:"resource"`

	// OPTIONAL. A security token that represents the identity of the acting party.
	ActorToken string

	// An identifier, that indicates the type of the security token in the
	// "actor_token" parameter.
	ActorTokenType string
}

// unmarshallTokenRequest validates a STS request, and extracts STS parameters from the request.
func (s *TokenExchangeD) unmarshallTokenRequest(req *http.Request) (*TokenExchangeRequest, error) {
	reqParam := &TokenExchangeRequest{}
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

	if encoding != "application/x-www-form-urlencoded" {
		return reqParam, errors.New("request content type is invalid")
	}

	if parseErr := req.ParseForm(); parseErr != nil {
		return reqParam, fmt.Errorf("failed to parse query from STS request: %v", parseErr)
	}
	//if req.PostForm.Get("grant_type") != meshauth.TokenExchangeGrantType {
	//	return reqParam, errors.New("request query grant_type is invalid")
	//}
	//// Only a JWT token is accepted.
	//if req.PostForm.Get("subject_token") == "" {
	//	return reqParam, errors.New("subject_token is empty")
	//}
	//if req.PostForm.Get("subject_token_type") != meshauth.SubjectTokenTypeJWT {
	//	return reqParam, errors.New("subject_token_type is invalid")
	//}

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
func (s *TokenExchangeD) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	reqParam, validationError := s.unmarshallTokenRequest(req)
	if validationError != nil {
		// If request is invalid, the error code must be "invalid_request".
		// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-16#section-2.2.2.
		s.sendErrorResponse(w, invalidRequest, validationError)
		return
	}

	j, err := s.Authn.CheckJWT(reqParam.SubjectToken)
	if err != nil {
		s.sendErrorResponse(w, invalidRequest, err)
		return
	}

	at, err := s.Generate(req.Context(), j, reqParam.Audience)
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

func (p *TokenExchangeD) generateSTSRespInner(token string) []byte {
	//exp, err := time.Parse(time.RFC3339Nano, atResp.ExpireTime)
	// Default token life time is 3600 seconds
	var expireInSec int64 = 3600
	//if err == nil {
	//	expireInSec = int64(time.Until(exp).Seconds())
	//}
	stsRespParam := &meshauth.TokenResponse{
		AccessToken:     token,
		IssuedTokenType: meshauth.AccessTokenType,
		TokenType:       "Bearer",
		ExpiresIn:       expireInSec,
	}
	statusJSON, _ := json.MarshalIndent(stsRespParam, "", " ")
	return statusJSON
}

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
func (s *TokenExchangeD) sendErrorResponse(w http.ResponseWriter, errorType string, errDetail error) {
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
func (s *TokenExchangeD) sendSuccessfulResponse(w http.ResponseWriter, tokenData []byte) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(tokenData); err != nil {
		log.Printf("failure in sending STS success response: %v", err)
		return
	}
}
