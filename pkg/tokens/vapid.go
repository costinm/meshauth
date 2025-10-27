// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tokens

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// RFC9292 - VAPID is an auth scheme based on public keys (EC256 only).

// https://github.com/emersion/webpush-go

// Vapid implements token issuance using VAPID and
// message encryption/decryption using webpush.
type Vapid struct {
	Private *ecdsa.PrivateKey

	// cached PublicKeyBase64 encoding of the public key, for EC256 VAPID.
	PublicKeyBase64 string

	EC256Key string
	EC256Pub string

	// EC256Priv is the 'raw' private key, in the standard format (not DER - i.e. D.Bytes())
	EC256Priv []byte `json:-`

	Domain string
	Name   string
}

func NewVAPID(m crypto.PrivateKey) *Vapid {
	if m == nil {
		m, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if pk, ok := m.(*ecdsa.PrivateKey); ok {
		v := &Vapid{
			Private: pk,
		}

		v.EC256Priv = pk.D.Bytes()
		v.EC256Key = base64.RawURLEncoding.EncodeToString(pk.D.Bytes())

		v.PublicKeyBase64 = base64.RawURLEncoding.EncodeToString(
			MarshalPublicKey(pk.Public()))

		return v
	}
	return nil
}

func MarshalPublicKey(key crypto.PublicKey) []byte {
	if k, ok := key.(*ecdsa.PublicKey); ok {

		return elliptic.Marshal(elliptic.P256(), k.X, k.Y)
		// starts with 0x04 == uncompressed curve
	}
	return nil
}

func RawKeyToPrivateKey(key, pub string) *ecdsa.PrivateKey {
	publicUncomp, _ := base64.RawURLEncoding.DecodeString(pub)
	privateUncomp, _ := base64.RawURLEncoding.DecodeString(key)

	// TODO: privateUncomp may be DER ?
	x, y := elliptic.Unmarshal(elliptic.P256(), publicUncomp)
	d := new(big.Int).SetBytes(privateUncomp)
	pubkey := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	pkey := ecdsa.PrivateKey{PublicKey: pubkey, D: d}

	return &pkey
}


// VAPIDToken creates a token with the specified endpoint, using configured Sub id
// and a default expiration (1h). The Mesh identity must be based on EC256.
//
// Format is "vapid t=TOKEN k=PUBKEY
//
// The optional (unauthenticated) Sub field is populated from Name@Domain or TrustDomain.
// The DMesh VIP is based on the public key of the signer.
// AUD is the URL from the subscription - for DMesh https://VIP:5228/s or
// https://DOMAIN:5228/s
func (v *Vapid) GetToken(ctx context.Context, aud string) (string, error) {
	jwt := JWT{}

	u, err := url.Parse(aud)
	if err != nil || len(u.Host) == 0 {
		jwt.Aud = []string{aud}
	} else {
		jwt.Aud = []string{"https://" + u.Host}
	}

	auth:= v

	if auth.Domain != "" {
		jwt.Sub = auth.Domain
		if auth.Name != "" {
			jwt.Sub = auth.Name + "@" + auth.Domain
		}
	}
	jwt.Exp = time.Now().Unix() + 3600

	token := jwt.Sign(auth.Private)

	return "vapid t=" + token + ", k=" + v.PublicKeyBase64, nil
}

func jwtParseAndCheckSig(tok string, pk crypto.PublicKey) (*JWT, error) {
	_, b, _, _, err := JwtRawParse(tok)
	if err != nil {
		return nil, err
	}

	return b, b.VerifySignature(pk)
}

// CheckVAPID verifies the signature and returns the token and public key.
// expCheck should be set to current time to set expiration
//
// Data is extracted from VAPID header - 'vapid' scheme and t/k params
//
// Does not check audience or other parms.
func CheckVAPID(tok string, now time.Time) (jwt *JWT, pub []byte, err error) {
	// Istio uses oidc - will make a HTTP request to fetch the .well-known from
	// iss.
	// provider, err := oidc.NewProvider(context.Background(), iss)
	// Provider uses verifier, using KeySet interface 'verifySignature(jwt)
	// The keyset is expected to be cached and configured (trusted)

	scheme, _, keys := ParseAuthorization(tok)
	if scheme != "vapid" {
		return nil, nil, errors.New("Unexected scheme " + scheme)
	}

	pubk := keys["k"]

	publicUncomp, err := base64.RawURLEncoding.DecodeString(pubk)
	if err != nil {
		return nil, nil, fmt.Errorf("VAPI: malformed jwt %v", err)
	}

	var pk crypto.PublicKey
	if len(publicUncomp) == 32 {
		pk = ed25519.PublicKey(publicUncomp)
	} else if len(publicUncomp) == 65 {
		x, y := elliptic.Unmarshal(elliptic.P256(), publicUncomp)
		pk = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	} else {
		return nil, nil, fmt.Errorf("VAPI: malformed jwt %d", len(pubk))
	}

	tok = keys["t"]
	b, err := jwtParseAndCheckSig(tok, pk)
	if err != nil {
		return nil, nil, err
	}

	if !now.IsZero() {
		expT := time.Unix(b.Exp, 0)
		if expT.Before(now) {
			return nil, nil, errors.New("Expired token")
		}
	}

	return b, publicUncomp, nil
}

// ParseAuthorization splits the Authorization header, returning the scheme and parameters.
// Used with the "scheme k=v,k=v" format.
func ParseAuthorization(auth string) (string, string, map[string]string) {
	auth = strings.TrimSpace(auth)
	params := map[string]string{}

	spaceIdx := strings.Index(auth, " ")
	if spaceIdx == -1 {
		return "", auth, params
	}

	scheme := auth[0:spaceIdx]
	auth = auth[spaceIdx:]

	if strings.Index(auth, "=") < 0 {
		return scheme, auth, params
	}

	pl := strings.Split(auth, ",")
	for _, p := range pl {
		p = strings.Trim(p, " ")
		kv := strings.Split(p, "=")
		if len(kv) == 2 {
			key := strings.Trim(kv[0], " ")
			params[key] = kv[1]
		}
	}

	return scheme, "", params
}



//// Send a message using the Web Push protocol to the recipient identified by the
//// given subscription object. If the client is nil then the default HTTP client
//// will be used. If the push service requires an authentication header (notably
//// Google Cloud Messaging, used by Chrome) then you can add that as the token
//// parameter.
//func Send(client *http.Client, sub *auth.Subscription, message, token string) (*http.Response, error) {
//	if client == nil {
//		client = http.DefaultClient
//	}
//
//	req, err := NewPushRequest(sub, message, token)
//	// Default TTL
//	req.Header.StartListener("ttl", "0")
//	if err != nil {
//		return nil, err
//	}
//
//	return client.Do(req)
//}

