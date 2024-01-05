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
	"context"
	"sync"
	"time"
)

// Token is a subset of oauth2.Token, to avoid a dep and keep it minimal and WASM-friendly.
type Token struct {
	// TODO: use JWT - with separate mapping for access tokens.
	Token  string
	Expiry time.Time
}

type JWTTokenCache struct {
	cache sync.Map
	m     sync.Mutex

	TokenSource TokenSource
}

func (c *JWTTokenCache) Token(ctx context.Context, aud string) (string, error) {
	if got, f := c.cache.Load(aud); f {
		t := got.(*JWT)
		if t.Expiry().After(time.Now().Add(-time.Minute)) {
			return t.Raw, nil
		}
	}

	// TODO: exponential backoff
	t, err := c.TokenSource.GetToken(ctx, aud)
	if err != nil {
		return "", err
	}

	j := DecodeJWT(t)

	c.cache.Store(aud, j)
	return t, nil
}

type TokenCache struct {
	cache sync.Map
	m     sync.Mutex

	TokenSource TokenSource

	// DefaultExpiration of tokens - 45 min if not set.
	// TokenSource doesn't deal with expiration, in almost all cases 1h retry is ok.
	DefaultExpiration time.Duration
}

func (c *TokenCache) Token(ctx context.Context, aud string) (string, error) {
	if got, f := c.cache.Load(aud); f {
		t := got.(Token)
		if t.Expiry.After(time.Now().Add(-time.Minute)) {
			return t.Token, nil
		}
	}

	t, err := c.TokenSource.GetToken(ctx, aud)

	if err != nil {
		return "", err
	}

	te := c.DefaultExpiration
	if te == 0 {
		te = 45 * time.Minute
	}
	c.cache.Store(aud, Token{t, time.Now().Add(te)})
	return t, nil
}
