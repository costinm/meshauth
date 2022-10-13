package meshauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
)

// Subscription holds the useful values from a PushSubscription object acquired
// from the browser.
//
// https://w3c.github.io/push-api/
//
// Returned as result of /subscribe
type Subscription struct {
	// Endpoint is the URL to send the Web Push message to. Comes from the
	// endpoint field of the PushSubscription.
	Endpoint string

	// Key is the client's public key. From the getKey("p256dh") or keys.p256dh field.
	Key []byte

	// Auth is a value used by the client to validate the encryption. From the
	// keys.auth field.
	// The encrypted aes128gcm will have 16 bytes authentication tag derived from this.
	// This is the pre-shared authentication secret.
	Auth []byte

	// Used by the UA to receive messages, as PUSH promises
	Location string
}

// SubscriptionFromJSON is a convenience function that takes a JSON encoded
// PushSubscription object acquired from the browser and returns a pointer to a
// node.
func SubscriptionFromJSON(b []byte) (*Subscription, error) {
	var sub struct {
		Endpoint string
		Keys     struct {
			P256dh string
			Auth   string
		}
	}
	if err := json.Unmarshal(b, &sub); err != nil {
		return nil, err
	}

	b64 := base64.URLEncoding.WithPadding(base64.NoPadding)

	// Chrome < 52 incorrectly adds padding when Base64 encoding the values, so
	// we need to strip that out
	key, err := b64.DecodeString(strings.TrimRight(sub.Keys.P256dh, "="))
	if err != nil {
		return nil, err
	}

	auth, err := b64.DecodeString(strings.TrimRight(sub.Keys.Auth, "="))
	if err != nil {
		return nil, err
	}

	return &Subscription{sub.Endpoint, key, auth, ""}, nil
}

func Verify(data []byte, pub []byte, sig []byte) error {
	hasher := crypto.SHA256.New()
	hasher.Write(data) //[0:64]) // only public key, for debug
	hash := hasher.Sum(nil)

	if len(pub) == 64 {
		// Expects 0x4 prefix - we don't send the 4.
		//x, y := elliptic.Unmarshal(curve, pub)
		x := new(big.Int).SetBytes(pub[0:32])
		y := new(big.Int).SetBytes(pub[32:64])
		if !elliptic.P256().IsOnCurve(x, y) {
			return errors.New("invalid public key")
		}

		pubKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		r := big.NewInt(0).SetBytes(sig[0:32])
		s := big.NewInt(0).SetBytes(sig[32:64])
		match := ecdsa.Verify(pubKey, hash, r, s)
		if match {
			return nil
		} else {
			return errors.New("failed to validate signature ")
		}
	} else if len(pub) == 32 {
		edp := ed25519.PublicKey(pub)
		if ed25519.Verify(edp, hash, sig) {
			return nil
		} else {
			return errors.New("failed to validate signature")
		}
	}
	return errors.New("unknown public key")
}
