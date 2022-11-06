package meshauth

// WIP: Minimal implementatio of OIDC, matching K8S. Other helpers for platform-specific tokens.
// Also includes JWT rule support based on Istio API

// A better option is github.com/coreos/go-oidc, which depends on gopkg.in/square/go-jose.v2

// In GKE, iss: format is https://container.googleapis.com/v1/projects/$PROJECT/locations/$LOCATION/clusters/$CLUSTER
// and the discovery doc is relative (i.e. standard). The keys are
// $ISS/jwks
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
//  "token_type": string,
//  "refresh_token": string,
//}
//
//

// JWTRule - from istio API, as json.
type JWTRule struct {

	// Example: https://foobar.auth0.com
	// Example: 1234567-compute@developer.gserviceaccount.com
	Issuer string `protobuf:"bytes,1,opt,name=issuer,proto3" json:"issuer,omitempty"`

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
	Audiences []string `protobuf:"bytes,2,rep,name=audiences,proto3" json:"audiences,omitempty"`

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
	// Note: Only one of jwks_uri and jwks should be used. jwks_uri will be ignored if it does.
	JwksUri string `protobuf:"bytes,3,opt,name=jwks_uri,json=jwksUri,proto3" json:"jwks_uri,omitempty"`

	// JSON Web Key Set of public keys to validate signature of the JWT.
	// See https://auth0.com/docs/jwks.
	//
	// Note: Only one of jwks_uri and jwks should be used. jwks_uri will be ignored if it does.
	//Jwks string `protobuf:"bytes,10,opt,name=jwks,proto3" json:"jwks,omitempty"`

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
	//ForwardOriginalToken bool     `protobuf:"varint,9,opt,name=forward_original_token,json=forwardOriginalToken,proto3" json:"forward_original_token,omitempty"`
}

type OIDCDiscDoc struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported"`
}
