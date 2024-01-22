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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
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

func (auth *MeshAuth) GetToken(ctx context.Context, aud string) (string, error) {
	jwt := &JWT{
		Aud: []string{aud},
	}
	return jwt.Sign(auth.Cert.PrivateKey), nil
}

// VAPIDToken creates a token with the specified endpoint, using configured Sub id
// and a default expiration (1h). The MeshAuth identity must be based on EC256.
//
// Format is "vapid t=TOKEN k=PUBKEY
//
// The optional (unauthenticated) Sub field is populated from Name@Domain or TrustDomain.
// The DMesh VIP is based on the public key of the signer.
// AUD is the URL from the subscription - for DMesh https://VIP:5228/s or
// https://DOMAIN:5228/s
func (auth *MeshAuth) VAPIDToken(aud string) string {
	jwt := JWT{}
	u, err := url.Parse(aud)
	if err != nil || len(u.Host) == 0 {
		jwt.Aud = []string{aud}
	} else {
		jwt.Aud = []string{"https://" + u.Host}
	}
	if auth.Domain != "" {
		jwt.Sub = auth.Domain
		if auth.Name != "" {
			jwt.Sub = auth.Name + "@" + auth.Domain
		}
	}
	jwt.Exp = time.Now().Unix() + 3600
	t, _ := json.Marshal(jwt)

	return auth.rawVAPIDSign(t)
}

func (auth *MeshAuth) rawVAPIDSign(t []byte) string {
	enc := base64.RawURLEncoding
	// Base64URL for the content of the token
	t64 := make([]byte, enc.EncodedLen(len(t)))
	enc.Encode(t64, t)
	c0 := *auth.Cert

	token := make([]byte, len(t)+len(vapidPrefix)+100)
	if _, ok := c0.PrivateKey.(*ecdsa.PrivateKey); ok {
		token = append(token[:0], vapidPrefix...)
	} else if _, ok := c0.PrivateKey.(ed25519.PrivateKey); ok {
		token = append(token[:0], vapidPrefixED...)
	} else {
		return ""
	}
	token = append(token, t64...)

	hasher := crypto.SHA256.New()
	hasher.Write(token)

	var sig []byte
	if ec, ok := c0.PrivateKey.(*ecdsa.PrivateKey); ok {
		if r, s, err := ecdsa.Sign(rand.Reader, ec, hasher.Sum(nil)); err == nil {
			// Vapid key is 32 bytes
			keyBytes := 32
			sig = make([]byte, 2*keyBytes)

			rBytes := r.Bytes()
			rBytesPadded := make([]byte, keyBytes)
			copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

			sBytes := s.Bytes()
			sBytesPadded := make([]byte, keyBytes)
			copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

			sig = append(sig[:0], rBytesPadded...)
			sig = append(sig, sBytesPadded...)

		}
	} else if ed, ok := c0.PrivateKey.(ed25519.PrivateKey); ok {
		sig, _ = ed.Sign(rand.Reader, hasher.Sum(nil), nil)
	}
	sigB64 := make([]byte, enc.EncodedLen(len(sig)))
	enc.Encode(sigB64, sig)

	token = append(token, dot...)
	token = append(token, sigB64...)

	return "vapid t=" + string(token) + ", k=" + auth.PublicKeyBase64
}

func jwtParseAndCheckSig(tok string, pk crypto.PublicKey) (*JWT, error) {
	h, b, txt, sig, err := JwtRawParse(tok)
	if err != nil {
		return nil, err
	}

	return JWTVerifySignature(h, b, txt, sig, pk)
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
