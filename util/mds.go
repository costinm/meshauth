package util

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Google metadata package OnGCE will probe the MDS server, checking the env
// variable first. It will also resolve metadata.google.internal. - but check
// if it is set to metadataIP, so iptables or env variable are required.

// https://cloud.google.com/compute/docs/metadata/querying-metadata

const (
	// metadataIP is the documented metadata server IP address.
	metadataIP = "169.254.169.254"

	// metadataHostEnv is the environment variable specifying the
	// GCE metadata hostname.  If empty, the default value of
	// metadataIP ("169.254.169.254") is used instead.
	// This is variable name is not defined by any spec, as far as
	// I know; it was made up for the Go package.
	metadataHostEnv = "GCE_METADATA_HOST"

	//userAgent = "gcloud-golang/0.1"
	userAgent = "uk8s-golang/0.1"
)

// MDS client interface. Modeled after metadata.go
// access token returned by MDS server

// TokenResponse stores all attributes sent as JSON in a successful STS
// response. These attributes are defined in
// https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-16#section-2.2.1
// Also returned by MDS and federated token.
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

type MDSRoundTripper struct {
	rt    http.RoundTripper
	token string
	exp   time.Time
}

// Subscribe calls Client.Subscribe on the default client.
func Subscribe(suffix string, fn func(v string, ok bool) error) error {
	return defaultClient.Subscribe(suffix, fn)
}

// Get calls Client.Get on the default client.
func Get(suffix string) (string, error) { return defaultClient.Get(suffix) }

func (m *MDSRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	t, err := defaultClient.Get("/instance/service-accounts/default/token")
	if err != nil {
		return nil, err
	}
	a := &TokenResponse{}
	json.Unmarshal([]byte(t), a)
	request.Header.Add("Authorization", "Bearer "+a.AccessToken)

	return m.rt.RoundTrip(request)
}

const tokenFile = "/var/run/secrets/tokens/ssh/token"

var defaultClient = &MDS{}

func newDefaultHTTPClient() *http.Client {
	// TODO: allow remote MDS, with self-signed or defined cert.
	return &http.Client{
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   2 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			IdleConnTimeout: 60 * time.Second,
		},
		Timeout: 5 * time.Second,
	}
}

// MDS provides access to the metadata server, tokens and host info.
type MDS struct {
	MDSBase string

	// TODO: cache, etc
	// TODO: plug other types of tokens and

	hc *http.Client

	// TODO: stats

}

// Subscribe subscribes to a value from the metadata service.
// The suffix is appended to "http://${GCE_METADATA_HOST}/computeMetadata/v1/".
// The suffix may contain query parameters.
//
// Subscribe calls fn with the latest metadata value indicated by the provided
// suffix. If the metadata value is deleted, fn is called with the empty string
// and ok false. Subscribe blocks until fn returns a non-nil error or the value
// is deleted. Subscribe returns the error value returned from the last call to
// fn, which may be nil when ok == false.
func (c *MDS) Subscribe(suffix string, fn func(v string, ok bool) error) error {
	const failedSubscribeSleep = time.Second * 5

	// First check to see if the metadata value exists at all.
	val, lastETag, err := c.getETag(suffix)
	if err != nil {
		return err
	}

	if err := fn(val, true); err != nil {
		return err
	}

	ok := true
	if strings.ContainsRune(suffix, '?') {
		suffix += "&wait_for_change=true&last_etag="
	} else {
		suffix += "?wait_for_change=true&last_etag="
	}
	for {
		val, etag, err := c.getETag(suffix + url.QueryEscape(lastETag))
		if err != nil {
			if _, deleted := err.(NotDefinedError); !deleted {
				time.Sleep(failedSubscribeSleep)
				continue // Retry on other errors.
			}
			ok = false
		}
		lastETag = etag

		if err := fn(val, ok); err != nil || !ok {
			return err
		}
	}
}

type NotDefinedError string

func (suffix NotDefinedError) Error() string {
	return fmt.Sprintf("metadata: GCE metadata %q not defined", string(suffix))
}

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
func (mds *MDS) GetTokenAud(aud string) (string, error) {
	// TODO: check well-known files
	if _, err := os.Stat(tokenFile); err == nil {
		data, err := ioutil.ReadFile(tokenFile)
		if err != nil {
			log.Println("Failed to read token file", err)
		} else {
			return string(data), nil
		}
	}

	ctx, cf := context.WithTimeout(context.Background(), 5*time.Second)
	defer cf()
	req, err := http.NewRequestWithContext(ctx, "GET", mds.MDSBase+fmt.Sprintf("instance/service-accounts/default/identity?audience=%s", aud), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := mds.hc.Do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server responeded with code=%d %s", resp.StatusCode, resp.Status)
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(b)), err
}

// getETag returns a value from the metadata service as well as the associated ETag.
// This func is otherwise equivalent to Get.
func (c *MDS) getETag(suffix string) (value, etag string, err error) {
	ctx := context.TODO()
	// Using a fixed IP makes it very difficult to spoof the metadata service in
	// a container, which is an important use-case for local testing of cloud
	// deployments. To enable spoofing of the metadata service, the environment
	// variable GCE_METADATA_HOST is first inspected to decide where metadata
	// requests shall go.
	host := os.Getenv(metadataHostEnv)
	if host == "" {
		// Using 169.254.169.254 instead of "metadata" here because Go
		// binaries built with the "netgo" tag and without cgo won't
		// know the search suffix for "metadata" is
		// ".google.internal", and this IP address is documented as
		// being stable anyway.
		host = metadataIP
	}
	suffix = strings.TrimLeft(suffix, "/")
	u := "http://" + host + "/computeMetadata/v1/" + suffix
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	req.Header.Set("User-Agent", userAgent)
	var res *http.Response
	var reqErr error
	retryer := newRetryer()
	for {
		res, reqErr = c.hc.Do(req)
		var code int
		if res != nil {
			code = res.StatusCode
		}
		if delay, shouldRetry := retryer.Retry(code, reqErr); shouldRetry {
			if err := sleep(ctx, delay); err != nil {
				return "", "", err
			}
			continue
		}
		break
	}
	if reqErr != nil {
		return "", "", reqErr
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return "", "", NotDefinedError(suffix)
	}
	all, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", "", err
	}
	if res.StatusCode != 200 {
		return "", "", &Error{Code: res.StatusCode, Message: string(all)}
	}
	return string(all), res.Header.Get("Etag"), nil
}

// Error contains an error response from the server.
type Error struct {
	// Code is the HTTP response status code.
	Code int
	// Message is the server response message.
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("code=%d msg=`%s`", e.Code, e.Message)
}

// Get returns a value from the metadata service.
// The suffix is appended to "http://${GCE_METADATA_HOST}/computeMetadata/v1/".
//
// If the GCE_METADATA_HOST environment variable is not defined, a default of
// 169.254.169.254 will be used instead.
//
// If the requested metadata is not defined, the returned error will
// be of type NotDefinedError.
func (c *MDS) Get(suffix string) (string, error) {
	val, _, err := c.getETag(suffix)
	return val, err
}
