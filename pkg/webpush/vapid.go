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

package meshauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/costinm/meshauth"
)

// RFC9292 - VAPID is an auth scheme based on public keys (EC256 only).

var (
	// encoded {"typ":"JWT","alg":"ES256"}
	vapidPrefix = []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.")
	// encoded {"typ":"JWT","alg":"EdDSA"}
	//https://tools.ietf.org/html/rfc8037
	vapidPrefixED = []byte("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.")
	dot           = []byte(".")
)

type Webpush struct {
	Mesh *meshauth.Mesh


	// cached PublicKeyBase64 encoding of the public key, for EC256 VAPID.
	PublicKeyBase64 string

	EC256Key string
	EC256Pub string

	// EC256Priv is the 'raw' private key, in the standard format (not DER - i.e. D.Bytes())
	EC256Priv []byte `json:-`

}

func New(m *meshauth.Mesh) *Webpush {
	v := &Webpush{Mesh: m}
	if pk, ok := m.Cert.PrivateKey.(*ecdsa.PrivateKey); ok {
		v.EC256Priv = pk.D.Bytes()
		v.EC256Key = base64.RawURLEncoding.EncodeToString(pk.D.Bytes())
		v.PublicKeyBase64 = base64.RawURLEncoding.EncodeToString(m.PublicKey)
	}
	return v
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
func (v *Webpush) GetToken(ctx context.Context, aud string) (string, error) {
	jwt := meshauth.JWT{}

	u, err := url.Parse(aud)
	if err != nil || len(u.Host) == 0 {
		jwt.Aud = []string{aud}
	} else {
		jwt.Aud = []string{"https://" + u.Host}
	}

	auth:= v.Mesh

	if auth.Domain != "" {
		jwt.Sub = auth.Domain
		if auth.Name != "" {
			jwt.Sub = auth.Name + "@" + auth.Domain
		}
	}
	jwt.Exp = time.Now().Unix() + 3600

	token := jwt.Sign(auth.Cert.PrivateKey)

	return "vapid t=" + token + ", k=" + v.PublicKeyBase64, nil
}

func jwtParseAndCheckSig(tok string, pk crypto.PublicKey) (*meshauth.JWT, error) {
	_, b, _, _, err := meshauth.JwtRawParse(tok)
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
func CheckVAPID(tok string, now time.Time) (jwt *meshauth.JWT, pub []byte, err error) {
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


// NewVapidRequest creates a valid Web Push HTTP request for sending a message
// to a subscriber, using Vapid authentication.
//
// You can add more headers to configure collapsing, TTL.
func(v *Webpush)  NewRequest(dest string, key, authK []byte,
		message string, ttlSec int, ma *meshauth.Mesh) (*http.Request, error) {

	// If the endpoint is GCM then we temporarily need to rewrite it, as not all
	// GCM servers support the Web Push protocol. This should go away in the
	// future.
	req, err := http.NewRequest("POST", dest, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("ttl", strconv.Itoa(ttlSec))

	if ma != nil {
		tok, _ := v.GetToken(req.Context(), dest)
		req.Header.Add("authorization", tok)
	}

	// If there is no payload then we don't actually need encryption
	if message != "" {
		ec := NewWebpushEncryption(key, authK)
		payload, err := ec.Encrypt([]byte(message))
		if err != nil {
			return nil, err
		}
		req.Body = ioutil.NopCloser(bytes.NewReader(payload))
		req.ContentLength = int64(len(payload))
		req.Header.Add("encryption",
			headerField("salt", ec.Salt))
		keys := headerField("dh", ec.SendPublic)
		req.Header.Add("crypto-key", keys)
		req.Header.Add("content-encoding", "aesgcm")
	}

	return req, nil
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

// A helper for creating the value part of the HTTP encryption headers
func headerField(headerType string, value []byte) string {
	return fmt.Sprintf(`%s=%s`, headerType, base64.RawURLEncoding.EncodeToString(value))
}
