package oidc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/costinm/meshauth"
	"github.com/costinm/meshauth/pkg/apis/authn"
)

// Minimal implementatio of OIDC, matching K8S. Other helpers for platform-specific tokens.
// Also includes RequestAuthentication/TrustConfig support based on Istio API.
//
// A more common option is github.com/coreos/go-oidc, which depends on
// gopkg.in/square/go-jose.v2 The meshauth/oidc package is using that library to download
// and convert the public keys.

//
// GCP also uses (https://github.com/GoogleCloudPlatform/secrets-store-csi-driver-provider-gcp/blob/v0.2.0/auth/auth.go):
// https://securetoken.googleapis.com/v1/identitybindingtoken
// "serviceAccount:<project>.svc.id.goog[<namespace>/<sa>]"
//
// In Istio, the WorkloadID token can be exchanged for access tokens:
// POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/
// service-<GCP project number>@gcp-sa-meshdataplane.iam.gserviceaccount.com:generateAccessToken
// Content-Type: application/json
// Authorization: Bearer <federated token>
// {
//  "Delegates": [],
//  "Scope": [
//      https://www.googleapis.com/auth/cloud-platform
//  ],
// }
//
// curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/my-gsa@my-project.iam.gserviceaccount.com/token"
// -H'Metadata-Flavor:Google'
//
// Access tokens:
// https://developers.google.com/identity/toolkit/reference/securetoken/rest/v1/token
// POST https://securetoken.googleapis.com/v1/token
// grant_type=authorization_code&code=ID_TOKEN
// grant_type=refresh_token&refresh_token=TOKEN
// Resp: {
//  "access_token": string,
//  "expires_in": string,
//  "token_type": string,`
//  "refresh_token": string,
//}
//
//

var onCloudrun = os.Getenv("ON_CLOUDRUN") != ""

// K8S k8s.io/apiserver/plugin/pkg/authenticator/token/oidc
// The test has a static JWK parser and helpers to convert from PEM
// Also uses jose.Thumbprint to compute Kid

// Authn handles JWK/OIDC authentication.
//
// A server may have different Authn configs for different listeners/hosts/routes - but typically one global
// config is more common.
type Authn struct {
	Cfg *authn.AuthnConfig

	Verify func(context.Context, *authn.TrustConfig, string) error

	Client *http.Client

	// Issuers is the map - config is using a list
	Issuers map[string]*authn.TrustConfig `json:-`
}

func NewAuthn(cfg *authn.AuthnConfig) *Authn {
	if cfg == nil {
		cfg = &authn.AuthnConfig{}
	}
	an := &Authn{Cfg: cfg, Issuers: map[string]*authn.TrustConfig{}}
	an.Client = http.DefaultClient

	for _, v := range cfg.Issuers {
		an.Issuers[v.Issuer] = v
	}

	return an
}


// AuthContext is a Context implementation holding auth info for a request.
type AuthContext struct {
	// Workload auth config
	MeshAuth *meshauth.Mesh

	// Parent
	Context context.Context

	// Slog
	Logger *slog.Logger

	Start time.Time

	// Metrics/Tracing

	// Auth info for this context
	Client string
	Peer   string

	JWTs []*meshauth.JWT
	// Original IP and metadata.
}

func (a *AuthContext) Deadline() (deadline time.Time, ok bool) {
	return a.Context.Deadline()
}

func (a *AuthContext) Done() <-chan struct{} {
	return a.Context.Done()
}

func (a *AuthContext) Err() error {
	return a.Context.Err()
}

// Value may return the AuthContext, if chained - or one of the fields.
// Otherwise will pass to parent.
func (a *AuthContext) Value(key any) any {
	if key == ContextKey {
		return a
	}
	return a.Context.Value(key)
}

const ContextKey = "meshAuth"

func WithContext(ctx context.Context, ma *meshauth.Mesh) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	// WithValue is a struct holding the key and value (any), passing to next context.
	// AuthContext holds multiple things in a map.
	return &AuthContext{MeshAuth: ma, Context: ctx}
	// instead of return context.WithValue(ctx, ContextKey, ma)
}

// Authn extracts credentials from request, applies the authn Rules to extact claims and
// sets the result in headers and context.
func (jauthn *Authn) Auth(actx *AuthContext, r *http.Request) error {
	a := r.Header["Authorization"]
	if len(a) == 0 {
		return nil
	}
	rawa := strings.TrimSpace(a[0])

	if strings.HasPrefix(rawa, BearerPrefix) ||
		strings.HasPrefix(rawa, "bearer ") { // cloudrun is lower case for some reason
		t := rawa[7:]

		jt, err := jauthn.CheckJWT(t)
		if err != nil {
			return err
		}

		actx.JWTs = append(actx.JWTs, jt)
		if jt.Email != "" {
			actx.Client = jt.Email
		} else {
			actx.Client = jt.Sub
		}
		if actx.Client != "" {
			r.Header["X-User"] = []string{actx.Client}
		}

		// Old experiment, not using it now.
	//} else if strings.HasPrefix(rawa, "vapid") {
	//	tok, pub, err := CheckVAPID(rawa, time.Now())
	//	if err != nil {
	//		return err
	//	}
	//	r.Header["X-VAPID-Pub"] = []string{string(pub)}
	//	r.Header["X-VAPID-Sub"] = []string{tok.Sub}
	//
	}
	return nil
}

var (
	TransientIssuerError = errors.New("transient issuer error")
	m sync.Mutex
)

// CheckJWT will validate the JWT and return the 'sub' (subject) of the token.
//
// If the JWT is invalid - fails signature, invalid claims - error is set.
//
// If the OIDC keys can't be fetched - a 500 response should be returned (?)
// This is indicated with a nil error and nil jwt.
func (ja *Authn) CheckJWT(token string) (jwt *meshauth.JWT, e error) {
	idt := meshauth.DecodeJWT(token)
	if idt == nil {
		return nil, errors.New("Invalid JWT")
	}

	// Special case: Cloudrun IAM will check the token and forward it without
	// signature for google.com and developer token.
	// We identify this by CLOUDRUN env
	if onCloudrun && idt.Iss == "https://accounts.google.com" {
		// Special case: Cloudrun IAM will check the token and forward it without
		// signature, for the developer token.
		return idt, nil
	}

	now := time.Now()
	expT := idt.Expiry()
	if expT.Before(now) {
		return nil, errors.New("expired token")
	}

	issuer := ja.Issuers[idt.Iss]
	if issuer == nil {
		return nil, errors.New("Unknown issuer " + idt.Iss)
	}

	var err error
	kid := idt.Head.Kid
	k := issuer.KeysByKid[kid]
	if k == nil {
		// Lazy Init
		m.Lock()
		k = issuer.KeysByKid[kid]
		if k == nil {
			err = ja.UpdateKeys(context.Background(), issuer)
		}
		m.Unlock()

		if err != nil {
			return nil, TransientIssuerError
		}
	}

	//if ja.Verify != nil {
	//err := ja.Verify(context.Background(), issuer, token)
	//if err != nil {
	//return nil, err
	//}
	k = issuer.KeysByKid[kid]
	if k == nil {
		// TODO: if single public, try it.
		return nil, errors.New("Unknown kid")
	}
	err = idt.VerifySignature(k)
	if err != nil {
		return nil, err
	}

	// TODO: check audience
	aud := ""
	for _, a := range idt.Aud {
		for _, b := range ja.Cfg.Audiences {
			if a == b || strings.HasPrefix(a, b) {
				aud = a
			}
		}
	}
	if aud == "" {
		slog.Info("Invalid aud ", "iss", idt.Iss,
			"aud", idt.Aud, "email", idt.Email) // , "tok", string(password))
		return nil, errors.New("invalid audience")
	}

	slog.Info("AuthJwt", "iss", idt.Iss,
		"aud", idt.Aud, "email", idt.Email) // , "tok", string(password))

	// Use email as sub
	if idt.Email != "" {
		idt.Sub = idt.Email
	}
	return idt, nil
}

func (a *Authn) CheckJwtMap(password string) (tok map[string]string, e error) {
	idt, err := a.CheckJWT(password)
	if err != nil {
		return nil, err
	}

	// TODO: check audience against config, domain

	return map[string]string{"sub": idt.Sub}, nil
}

const BearerPrefix = "Bearer "

// UpdateWellKnown downloads the JWKS from the well-known location
// Extracted from go-oidc
func (ja *Authn) UpdateWellKnown(ctx context.Context, issuer string, td *authn.TrustConfig) error {
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, "GET", wellKnown, nil)
	if err != nil {
		return err
	}
	resp, err := ja.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, body)
	}
	td.OIDC = &authn.OIDCDiscDoc{}
	err = json.Unmarshal(body, td.OIDC)
	if err != nil {
		return fmt.Errorf("oidc: failed to decode provider discovery object: %v", err)
	}

	if td.OIDC.Issuer != issuer {
		return fmt.Errorf("oidc: issuer did not match the issuer returned by provider, expected %q got %q", issuer,
			td.OIDC.Issuer)
	}
	td.JwksUri = td.OIDC.JWKSURL
	return nil
}

// Init the JWT map - can also be used to reconfigure.
func (ja *Authn) FetchAllKeys(ctx context.Context, issuers []*authn.TrustConfig) error {
	if len(issuers) == 0 {
		return nil
	}
	t0 := time.Now()
	errs := []error{}
	for _, i := range issuers {
		err := ja.UpdateKeys(ctx, i)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if time.Since(t0) > 1*time.Second {
		slog.Info("Issuer init ", "d", time.Since(t0))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// UpdateKeys will populate the Keys field, by fetching the keys.
func (ja *Authn) UpdateKeys(ctx context.Context, i *authn.TrustConfig) error {
	if len(i.JwksUri) == 0 {
		err := ja.UpdateWellKnown(context.Background(), i.Issuer, i)
		if err != nil {
			return err
		}
	}
	if len(i.JwksUri) > 0 {
		// oidc.KeySet embed and refresh cached jose.JSONWebKey
		// It is unfortunately just an interface - doesn't expose the actual keys.
		err := ja.FetchKeys(ctx, i)
		if err != nil {
			return err
		}
	}

	if len(i.Jwks) > 0 {
		err := ja.ConvertJWKS(i)
		if err != nil {
			return err
		}
	}

	return nil
}

func (ja *Authn) FetchKeys(ctx context.Context, i *authn.TrustConfig) error {
	url := i.JwksUri
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := ja.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc: get keys failed: %s %s", resp.Status, body)
	}

	// TODO: If the server doesn't provide cache control headers, assume the
	// keys expire in 24h.

	i.Jwks = string(body)
	return nil
}

func (ja *Authn) ConvertJWKS(i *authn.TrustConfig) error {
	body := []byte(i.Jwks)
	var keySet JSONWebKeySet
	err := json.Unmarshal(body, &keySet)
	if err != nil {
		return fmt.Errorf("oidc: failed to decode keys: %v %s", err, body)
	}

	// Map of 'kid' to key
	i.KeysByKid = map[string]interface{}{}
	for _, ks := range keySet.Keys {
		i.KeysByKid[ks.Kid], err = ks.Key()
		if err != nil {
			return err
		}
	}
	return nil
}

type JSONWebKeySet struct {
	Keys []rawJSONWebKey `json:"keys"`
}

// rawJSONWebKey represents a public or private key in JWK format, used for parsing/serializing.
// From jose.
type rawJSONWebKey struct {
	Use string      `json:"use,omitempty"`
	Kty string      `json:"kty,omitempty"`
	Kid string      `json:"kid,omitempty"`
	Crv string      `json:"crv,omitempty"`
	Alg string      `json:"alg,omitempty"`
	K   *byteBuffer `json:"k,omitempty"`
	X   *byteBuffer `json:"x,omitempty"`
	Y   *byteBuffer `json:"y,omitempty"`
	N   *byteBuffer `json:"n,omitempty"`
	E   *byteBuffer `json:"e,omitempty"`
	// -- Following fields are only used for private keys --
	// RSA uses D, P and Q, while ECDSA uses only D. Fields Dp, Dq, and Qi are
	// completely optional. Therefore for RSA/ECDSA, D != nil is a contract that
	// we have a private key whereas D == nil means we have only a public key.
	D  *byteBuffer `json:"d,omitempty"`
	P  *byteBuffer `json:"p,omitempty"`
	Q  *byteBuffer `json:"q,omitempty"`
	Dp *byteBuffer `json:"dp,omitempty"`
	Dq *byteBuffer `json:"dq,omitempty"`
	Qi *byteBuffer `json:"qi,omitempty"`
	// Certificates
	X5c       []string `json:"x5c,omitempty"`
	X5u       *url.URL `json:"x5u,omitempty"`
	X5tSHA1   string   `json:"x5t,omitempty"`
	X5tSHA256 string   `json:"x5t#S256,omitempty"`
}

// byteBuffer represents a slice of bytes that can be serialized to url-safe base64.
type byteBuffer struct {
	data []byte
}

func (b *byteBuffer) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.base64())
}

func (b *byteBuffer) UnmarshalJSON(data []byte) error {
	var encoded string
	err := json.Unmarshal(data, &encoded)
	if err != nil {
		return err
	}

	if encoded == "" {
		return nil
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}

	*b = *newBuffer(decoded)

	return nil
}

func newBuffer(data []byte) *byteBuffer {
	if data == nil {
		return nil
	}
	return &byteBuffer{
		data: data,
	}
}

func (b *byteBuffer) base64() string {
	return base64.RawURLEncoding.EncodeToString(b.data)
}

func (b byteBuffer) bigInt() *big.Int {
	return new(big.Int).SetBytes(b.data)
}

func (b byteBuffer) toInt() int {
	return int(b.bigInt().Int64())
}

func (key *rawJSONWebKey) rsaPublicKey() (*rsa.PublicKey, error) {
	if key.N == nil || key.E == nil {
		return nil, fmt.Errorf("square/go-jose: invalid RSA key, missing n/e values")
	}

	return &rsa.PublicKey{
		N: key.N.bigInt(),
		E: key.E.toInt(),
	}, nil
}

func fromRsaPublicKey(pub *rsa.PublicKey) *rawJSONWebKey {
	return &rawJSONWebKey{
		Kty: "RSA",
		N:   newBuffer(pub.N.Bytes()),
		E:   newBufferFromInt(uint64(pub.E)),
	}
}

func (key *rawJSONWebKey) ecPublicKey() (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch key.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("square/go-jose: unsupported elliptic curve '%s'", key.Crv)
	}

	if key.X == nil || key.Y == nil {
		return nil, errors.New("square/go-jose: invalid EC key, missing x/y values")
	}

	// The length of this octet string MUST be the full size of a coordinate for
	// the curve specified in the "crv" parameter.
	// https://tools.ietf.org/html/rfc7518#section-6.2.1.2
	if curveSize(curve) != len(key.X.data) {
		return nil, fmt.Errorf("square/go-jose: invalid EC public key, wrong length for x")
	}

	if curveSize(curve) != len(key.Y.data) {
		return nil, fmt.Errorf("square/go-jose: invalid EC public key, wrong length for y")
	}

	x := key.X.bigInt()
	y := key.Y.bigInt()

	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("square/go-jose: invalid EC key, X/Y are not on declared curve")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func (key *rawJSONWebKey) Key() (interface{}, error) {
	switch key.Kty {
	case "EC":
		return key.ecPublicKey()
	case "RSA":
		return key.rsaPublicKey()

	}
	return nil, errors.New("Key not supported yet " + key.Kty)
}

func fromEcPublicKey(pub *ecdsa.PublicKey) (*rawJSONWebKey, error) {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil, fmt.Errorf("square/go-jose: invalid EC key (nil, or X/Y missing)")
	}

	name, err := curveName(pub.Curve)
	if err != nil {
		return nil, err
	}

	size := curveSize(pub.Curve)

	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	if len(xBytes) > size || len(yBytes) > size {
		return nil, fmt.Errorf("square/go-jose: invalid EC key (X/Y too large)")
	}

	key := &rawJSONWebKey{
		Kty: "EC",
		Crv: name,
		X:   newFixedSizeBuffer(xBytes, size),
		Y:   newFixedSizeBuffer(yBytes, size),
	}

	return key, nil
}

func newFixedSizeBuffer(data []byte, length int) *byteBuffer {
	if len(data) > length {
		panic("square/go-jose: invalid call to newFixedSizeBuffer (len(data) > length)")
	}
	pad := make([]byte, length-len(data))
	return newBuffer(append(pad, data...))
}

func newBufferFromInt(num uint64) *byteBuffer {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, num)
	return newBuffer(bytes.TrimLeft(data, "\x00"))
}

// Get JOSE name of curve
func curveName(crv elliptic.Curve) (string, error) {
	switch crv {
	case elliptic.P256():
		return "P-256", nil
	case elliptic.P384():
		return "P-384", nil
	case elliptic.P521():
		return "P-521", nil
	default:
		return "", fmt.Errorf("square/go-jose: unsupported/unknown elliptic curve")
	}
}

// Get size of curve in bytes
func curveSize(crv elliptic.Curve) int {
	bits := crv.Params().BitSize

	div := bits / 8
	mod := bits % 8

	if mod == 0 {
		return div
	}

	return div + 1
}
