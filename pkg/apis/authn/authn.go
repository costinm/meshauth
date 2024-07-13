package authn

import (
	"sync"
	"time"
)

// AuthnConfig specifies trusted sources for incoming authentication.
//
// Common case is as a global config, but may be specified per listener.
//
// Unlike Istio, this also covers SSH and Cert public keys - treating all signed mechanisms the same.
type AuthnConfig struct {
	// Trusted issuers for auth.
	//
	Issuers []*TrustConfig `json:"trust,omitempty"`

	// Top level audiences. The rule may have a custom audience as well, if it matches this is
	// ignored.
	// If empty, the hostname is used as a default.
	Audiences []string `json:"aud,omitempty"`
}

// Configure the settings for one trusted identity provider. This is primarily used for server side authenticating
// clients, but may also be used for clients authenticating servers - it defines what is trusted to provided identities.
//
// Extended from Istio JWTRule - but unified with certificate providers.
type TrustConfig struct {

	// Example: https://foobar.auth0.com
	// Example: 1234567-compute@developer.gserviceaccount.com (for tokens signed by a GSA)
	// In GKE, format is https://container.googleapis.com/v1/projects/$PROJECT/locations/$LOCATION/clusters/$CLUSTER
	// and the discovery doc is relative (i.e. standard).
	// The keys typically are $ISS/jwks - but OIDC document should be loaded.
	//
	// Must match the Issuer in the JWT token.
	// As 'converged' auth, this is also used to represent SSH or TLS CAs.
	Issuer string `json:"issuer,omitempty"`

	// Delegation indicates a mechanism of delegation - can be:
	// - TODO: a URL indicating a different issuer that is replacing the signature.
	// - NO_SIGNATURE - indicates that the workload is running in a Cloudrun-like env, where
	// the JWT is verified by a frontend and replaced with a token without signature.
	// - header:NAME - the jwt is decoded and placed in a header.
	// - xfcc -
	//Delegation string

	// Identification for the frontend that has validated the identity
	//
	//Delegator string

	// The list of JWT
	// [audiences](https://tools.ietf.org/html/rfc7519#section-4.1.3).
	// that are allowed to access. A JWT containing any of these
	// audiences will be accepted.
	//
	// The service name will be accepted if audiences is empty.
	//
	// Example:
	//
	// ```yaml
	// audiences:
	// - bookstore_android.apps.example.com
	//   bookstore_web.apps.example.com
	// ```
	// Istio had this next to issuer - in meshauth it is one level higher, all
	// issuers can use the same aud ( it is based on hostname of the node or service )
	//Audiences []string `protobuf:"bytes,2,rep,name=audiences,proto3" json:"audiences,omitempty"`

	// URL of the provider's public key set to validate signature of the
	// JWT. See [OpenID Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).
	//
	// Optional if the key set document can either (a) be retrieved from
	// [OpenID
	// Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) of
	// the issuer or (b) inferred from the email domain of the issuer (e.g. a
	// Google service account).
	//
	// Example: `https://www.googleapis.com/oauth2/v1/certs`
	//
	//
	// Note: Only one of jwks_uri and jwks should be used. jwks_uri will be ignored if it does.
	JwksUri string `json:"jwks_uri,omitempty"`

	// JSON Web Key Set of public keys to validate signature of the JWT.
	// See https://auth0.com/docs/jwks.
	//
	// Note: In Istio, only one of jwks_uri and jwks should be used. jwks_uri
	// will be ignored if Jwks is present - but it doesn't seem right.
	//
	// TODO: mutating webhook to populate this field, controller JOB to rotate
	Jwks string `protobuf:"bytes,10,opt,name=jwks,proto3" json:"jwks,omitempty"`

	// List of header locations from which JWT is expected. For example, below is the location spec
	// if JWT is expected to be found in `x-jwt-assertion` header, and have "Bearer " prefix:
	// ```
	//   fromHeaders:
	//   - name: x-jwt-assertion
	//     prefix: "Bearer "
	// ```
	//FromHeaders []*JWTHeader `protobuf:"bytes,6,rep,name=from_headers,json=fromHeaders,proto3" json:"from_headers,omitempty"`
	// List of query parameters from which JWT is expected. For example, if JWT is provided via query
	// parameter `my_token` (e.g /path?my_token=<JWT>), the config is:
	// ```
	//   fromParams:
	//   - "my_token"
	// ```
	//FromParams []string `protobuf:"bytes,7,rep,name=from_params,json=fromParams,proto3" json:"from_params,omitempty"`

	// This field specifies the header name to output a successfully verified JWT payload to the
	// backend. The forwarded data is `base64_encoded(jwt_payload_in_JSON)`. If it is not specified,
	// the payload will not be emitted.
	// OutputPayloadToHeader string `protobuf:"bytes,8,opt,name=output_payload_to_header,json=outputPayloadToHeader,proto3" json:"output_payload_to_header,omitempty"`

	// If set to true, the orginal token will be kept for the ustream request. Default is false.
	//ForwardOriginalToken bool `protobuf:"varint,9,opt,name=forward_original_token,json=forwardOriginalToken,proto3" json:"forward_original_token,omitempty"`

	// PEM provides the set of public keys or certificates in-line.
	//
	// Not recommended - use pem_location instead so it can be reloaded, unless the trust config is reloaded itself.
	//
	// Extension to Istio JwtRule - specify the public key as PEM. This may include multiple
	// public keys or certificates. This will be populated by a mutating webhook and updated
	// by a job.
	PEM string `json:"pem,omitempty"`

	// Location of a PEM file providing the public keys or certificates of the trusted source.
	// Directory or URL. If provided, will be reloaded periodically or based on expiration time.
	PEMLocation string `json:"pem_location,omitempty"`

	// Extension to Isio JwtRule - cached subset of the OIDC discovery document
	OIDC *OIDCDiscDoc `json:"oidc,omitempty"`

	// Not stored - the actual keys or verifiers for this issuer.
	Key interface{} `json:-"`

	// KeysById is populated from the Jwks config or PEM
	KeysByKid map[string]interface{} `json:-`

	m         sync.Mutex `json:-`
	lastFetch time.Time  `json:-`
	exp       time.Time  `json:-`
}

// WIP: discovery document returned when fetching the 'issuer' well known location
//
//	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
//
// Example: curl -v https://accounts.google.com/.well-known/openid-configuration
type OIDCDiscDoc struct {
	// Should match the one in the URL
	Issuer string `json:"issuer,omitempty"`

	// Same as the URI in the Istio config - contains the keys.
	// Example: "https://www.googleapis.com/oauth2/v3/certs"
	JWKSURL string `json:"jwks_uri,omitempty"`

	// Not used
	AuthURL       string `json:"authorization_endpoint,omitempty"`
	DeviceAuthURL string `json:"device_authorization_endpoint,omitempty"`
	TokenURL      string `json:"token_endpoint,omitempty"`
	UserInfoURL   string `json:"userinfo_endpoint,omitempty"`

	Algorithms []string `json:"id_token_signing_alg_values_supported,omitempty"`
}


