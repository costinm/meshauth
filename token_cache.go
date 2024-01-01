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
	Token  string
	Expiry time.Time
}

type TokenCache struct {
	cache sync.Map

	STS func(ctx context.Context, host string) (string, error)
	m   sync.Mutex
}

func NewTokenCache(sts func(ctx context.Context, host string) (string, error)) *TokenCache {
	return &TokenCache{STS: sts}
}

func (c *TokenCache) Token(ctx context.Context, host string) (string, error) {
	if got, f := c.cache.Load(host); f {
		t := got.(Token)
		if t.Expiry.After(time.Now().Add(-time.Minute)) {
			return t.Token, nil
		}
	}

	t, err := c.STS(ctx, host)

	if err != nil {
		return "", err
	}

	c.cache.Store(host, Token{t, time.Now().Add(45 * time.Minute)})
	return t, nil
}
