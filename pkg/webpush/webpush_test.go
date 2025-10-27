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

package webpush

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"testing"
)

var (
	// The hex representation of the expected end result of encrypting the test
	// message using the mock salt and keys and the fake subscription.
	expectedCiphertextHex = "c29da35b8ad084b3cda4b3c20bd9d1bb9098dfb5c8e7c2e3a67fe7c91ff887b72f"

	// A fake subscription created with random key and auth values
	subscriptionJSON = []byte(`{
		"endpoint": "https://example.com/",
		"keys": {
			"p256dh": "BCXJI0VW7evda9ldlo18MuHhgQVxWbd0dGmUfpQedaD7KDjB8sGWX5iiP7lkjxi-A02b8Fi3BMWWLoo3b4Tdl-c=",
			"auth": "WPF9D0bTVZCV2pXSgj6Zug=="
		}
	}`)

	//message = `I am the walrus`

	plain = "When I grow up, I want to be a watermelon"

	rfcPlaintext = "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24"

	// Test vectors from RFC - UA keys and auth
	rfcUAPublic  = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
	rfcUAPrivate = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"
	rfcAuth   = "BTBZMqHH6r4Tts7J_aSIgg"


	// Test vectors from RFC - the ephemeral sender key and the resulting
	// cipher text
	rfcAsPublic  = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
	rfcAsPrivate = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
	rfcSalt   = "DGv6ra1nlYgDCS1FRnbzlw"

	rfcCipher = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN" //"8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ"//"6nqAQUME8hNqw5J3kl8cpVVJylXKYqZOeseZG8UueKpA"
)


// TestRfcVectors uses the values given in the RFC for HTTP encryption to verify
// that the code conforms to the RFC
func TestRfcVectors(t *testing.T) {
	//defer stubFuncs(rfcSalt, rfcKeys)()

	b64 := base64.URLEncoding.WithPadding(base64.NoPadding)

	auth, err := b64.DecodeString(rfcAuth)
	if err != nil {
		t.Error(err)
	}
	salt, err := b64.DecodeString(rfcSalt)
	if err != nil {
		t.Error(err)
	}
	key, err := b64.DecodeString(rfcUAPublic)
	if err != nil {
		t.Error(err)
	}
	asPublic, err := b64.DecodeString(rfcAsPublic)
	if err != nil {
		t.Error(err)
	}
	asPrivate, err := b64.DecodeString(rfcAsPrivate)
	if err != nil {
		t.Error(err)
	}
	msg, err := b64.DecodeString(rfcPlaintext)
	if err != nil {
		t.Error(err)
	}

	ec := &WebpushEncryption{
		Auth:     auth,
		UAPublic: key,

		// Random usually - but set to match RFC
		SendPublic:  asPublic,
		SendPrivate: asPrivate,

		Salt: salt,
	}

	_, err = ec.Encrypt(msg)
	if err != nil {
		t.Error(err)
	}

	expCiphertext, err := b64.DecodeString(rfcCipher)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(ec.Ciphertext, expCiphertext) {
		t.Errorf("Ciphertext was %v, expected %v", ec.Ciphertext, expCiphertext)
	}
}

func Encrypt(key []byte, auth []byte, m string) (*WebpushEncryption, error) {
	ec := &WebpushEncryption{
		Auth:     auth,
		UAPublic: key,
	}

	_, err := ec.Encrypt([]byte(m))
	return ec, err
}

func TestSharedSecret(t *testing.T) {
	serverPrivateKey, serverPub, _ := randomKey()
	invalidPub, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	_, err := sharedSecret(curve, invalidPub, serverPrivateKey, serverPub)
	if err == nil {
		t.Error("Expected an error due to invalid public key")
	}

	_, err = sharedSecret(curve, nil, serverPrivateKey, serverPub)
	if err == nil {
		t.Error("Expected an error due to nil key")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	sub, _ := SubscriptionFromJSON(subscriptionJSON)
	for i := 0; i < b.N; i++ {
		Encrypt(sub.Key, sub.Auth, "Hello world")
	}
}

func TestEncrypt(t *testing.T) {
	sub, _ := SubscriptionFromJSON(subscriptionJSON)
	_, err := Encrypt(sub.Key, sub.Auth, "Hello world")
	if err != nil {
		t.Fatal(err)
	}

}

//func BenchmarkEncryptWithKey(b *testing.B) {
//	sub, _ := WebpushSubscriptionToDest(subscriptionJSON)
//	plain := []byte("Hello world")
//	serverPrivateKey, serverPublicKey, _ := randomKey()
//
//	for i := 0; i < b.N; i++ {
//		EncryptWithTempKey(sub.Key, sub.Auth, plain, serverPrivateKey, serverPublicKey)
//	}
//}

func Test2Way(t *testing.T) {
	b64 := base64.URLEncoding.WithPadding(base64.NoPadding)

	subPriv, subPub, err := randomKey()
	auth, err := b64.DecodeString(rfcAuth)
	sub := &Subscription{
		Endpoint:             "https://foo.com",
		Auth:      auth,
		Key: subPub,
	}
	result, err := Encrypt(sub.Key, sub.Auth, plain)
	if err != nil {
		t.Error(err)
	}

	dc := WebpushEncryption{
		UAPrivate: subPriv,
		UAPublic:  subPub,
		Auth:      auth,
	}
	plainR, err := dc.Decrypt(result.Ciphertext)

	// assumes 2-bytes padding length == 0
	if err != nil {
		t.Error("Decrypt error ", err)
	} else if string(plainR) != plain {
		t.Error(plain, plainR)
		return
	}
}

func Test2WayRFC(t *testing.T) {
	b64 := base64.URLEncoding.WithPadding(base64.NoPadding)

	subPriv, _ := base64.RawURLEncoding.DecodeString(rfcUAPrivate)
	subPub, _ := base64.RawURLEncoding.DecodeString(rfcUAPublic)
	auth, err := b64.DecodeString(rfcAuth)
	sub := &Subscription{
		Endpoint:             "https://foo.com",
		Auth:      auth,
		Key: subPub,
	}
	result := &WebpushEncryption{
		Auth:     auth,
		UAPublic: sub.Key,
	}

	_, err = result.Encrypt([]byte(plain))

	if err != nil {
		t.Fatal(err)
	}

	dc := WebpushEncryption{
		UAPrivate: subPriv,
		UAPublic:  subPub,
		Auth:      auth,
	}
	plainR, err := dc.Decrypt(result.Ciphertext)

	// assumes 2-bytes padding length == 0
	if err != nil {
		t.Fatal("Decrypt error ", err)
	} else if string(plainR) != plain {
		t.Error(plain, plainR)
		return
	}
}

func TestWebpush(t *testing.T) {

	// ecdh_secret=kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs

	// key_info="V2ViUHVzaDogaW5mbwAEJXGyvs3942BVGq8e0PTNNmwRzr5VX4m8t7GGpTM5FzFo7OLr4BhZe9MEebhuPI-OztV3ylkYfpJGmQ22ggCLDgT-M_SrDepxkU21WCP3O1SUj0EwbZIHMtu5pZpTKGSCIA5Zent7wmC6HCJ5mFgJkuk5cwAvMBKiiujwa7t45ewP"
	//
	// ikm =S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg
	//
	// prk=09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc

	// cek_info=Q29udGVudC1FbmNvZGluZzogYWVzMTI4Z2NtAA
	// cek=oIhVW04MRdy2XN9CiKLxTg

	// nonce_info=Q29udGVudC1FbmNvZGluZzogbm9uY2UA
	// nonce=4h_95klXJ5E_qnoN
	//
	// salt, recsize, app pubkey
	// header="DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"

	//The push message plaintext has the padding delimiter octet (0x02)
	//appended to produce:

	// plain_prefix = "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24C"
	// cipher: 8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ


	authB, _ := base64.RawURLEncoding.DecodeString(rfcAuth)
	rfcUAPubBytes, _ := base64.RawURLEncoding.DecodeString(rfcUAPublic,)
	ec := NewWebpushEncryption(rfcUAPubBytes, authB)

	// To reproduce the same output, use the key from the RFC.
	// Sender private and public keys
	sprivB, _ := base64.RawURLEncoding.DecodeString(rfcAsPrivate)
	spubB, _ := base64.RawURLEncoding.DecodeString(rfcAsPublic)
	ec.SendPrivate = sprivB // RawKeyToPrivateKey(spriv)
	ec.SendPublic = spubB
	ec.Salt, _ = base64.RawURLEncoding.DecodeString(rfcSalt)

	cipher, err := ec.Encrypt([]byte(plain))
	if err != nil {
		t.Fatal(err)
	}

	rfcTestBodyBytes, _ := base64.RawURLEncoding.DecodeString(rfcCipher)
	if !bytes.Equal(cipher, rfcTestBodyBytes) {
		t.Error("Failed to encrypt")
	}

	log.Println("ENCRYPTED OK")

	//RawKeyToPrivateKey(rfcUAPrivate, rfcUAPublic)

	dc := NewWebpushDecryption(rfcUAPrivate, rfcUAPubBytes, authB)
	plain1, err := dc.Decrypt(cipher)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(plain1, []byte(plain)) {
		t.Error("Failed to decrypt")
	}

	ec1 := NewWebpushEncryption(rfcUAPubBytes, authB)
	cipher, _ = ec1.Encrypt([]byte{1})
	if len(cipher) != 104 {
		t.Error("One byte expecting 104 got ", len(cipher))
	}
	log.Printf("Encrypt 1 byte to %d", len(cipher))

	ec2 := NewWebpushDecryption(rfcUAPrivate, rfcUAPubBytes, authB)
	plainB, err := ec2.Decrypt(cipher)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plainB, []byte{1}) {
		t.Error("Failed to decrypt")
	}
}

// ========== Old VAPID JWT tests =============



/*
  RFC 8291, Appendix A: https://tools.ietf.org/html/rfc8291#appendix-A


  User agent public key (ua_public):
		BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4

  User agent private key (ua_private):
		q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94

  Authentication secret (auth_secret):  BTBZMqHH6r4Tts7J_aSIgg

	Not used ( random in this test):

   Plaintext:  V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24
   Application server public key (as_public):
     BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8

   Application server private key (as_private):
		 yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw

   Salt:  DGv6ra1nlYgDCS1FRnbzlw


*/

func TestSendWebPush(t *testing.T) {

	//POST /push/JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV HTTP/1.1
	// Host: push.example.net
	//TTL: 10
	// Content-Length: 33
	// Content-Encoding: aes128gcm

	uaPublic, err := base64.RawURLEncoding.DecodeString(rfcUAPublic)
	if err != nil {
		t.Fatal(err)
	}
	authSecret, err := base64.RawURLEncoding.DecodeString(rfcAuth)
	if err != nil {
		t.Fatal(err)
	}

	// Test server checks that the request is well-formed
	ts := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {

		defer request.Body.Close()

		body, err := ioutil.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}

		message := `I am the walrus` // 15B

		// Old overhead: 2 bytes padding and 16 bytes auth tag
		// New overhead: 103 bytes
		expectedLength := len(message) + 103

		// Real: 118 (previous overhead:
		if len(body) != expectedLength {
			t.Logf("Expected body to be length %d, was %d", expectedLength, len(body))
		}

		if request.Header.Get("TTL") == "" {
			t.Error("Expected TTL header to be set")
		}

		if request.Header.Get("Content-Encoding") != "aesgcm" {
			t.Errorf("Expected Content-Encoding header to be aesgcm, got %v", request.Header.Get("Content-Encoding"))
		}

		if !strings.HasPrefix(request.Header.Get("Crypto-Key"), "dh=") {
			t.Errorf("Expected Crypto-Key header to have a dh field, got %v", request.Header.Get("Crypto-Key"))
		}

		if !strings.HasPrefix(request.Header.Get("Encryption"), "salt=") {
			t.Errorf("Expected Encryption header to have a salt field, got %v", request.Header.Get("Encryption"))
		}

		dc := NewWebpushDecryption(rfcUAPrivate, uaPublic, authSecret)

		plain, err := dc.Decrypt(body)
		if err != nil {
			t.Fatal(err)
			writer.WriteHeader(502)
			return
		}

		if !bytes.Equal(plain, []byte(message)) {
			t.Error("Expected", message, "got", string(plain))
			writer.WriteHeader(501)
			return
		}

		writer.WriteHeader(201)
	}))
	defer ts.Close()

	//sub := &Subscription{ts.URL, key, a, ""}
	message := "I am the walrus"
	pushReq, err := NewRequest(ts.URL+"/push/", uaPublic,
		authSecret, message, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	cl := ts.Client()
	//rb, _ := httputil.DumpRequest(pushReq, true)
	//log.Println(string(rb))
	res, err := cl.Do(pushReq)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 201 {
		t.Error("Expected 201, got", res.StatusCode)
	}
	//rb, _ = httputil.DumpResponse(res, true)
	//log.Println(string(rb))
}

func TestSendTickle(t *testing.T) {
	// Test server checks that the request is well-formed
	ts := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(200)

		defer request.Body.Close()

		body, err := ioutil.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}

		if len(body) != 0 {
			t.Errorf("Expected body to be length 0, was %d", len(body))
		}

		if request.Header.Get("TTL") == "" {
			t.Error("Expected TTL header to be set")
		}
	}))
	defer ts.Close()

	//sub := &Subscription{Endpoint: ts.URL}

	pushReq, err := NewRequest(ts.URL+"/push/", nil, nil, "", 0, nil)
	if err != nil {
		t.Error(err)
	}
	cl := ts.Client()
	httputil.DumpRequest(pushReq, true)
	res, err := cl.Do(pushReq)
	if err != nil {
		t.Error(err)
	}
	httputil.DumpResponse(res, true)
}

func TestSubscriptionFromJSON(t *testing.T) {
	_, err := SubscriptionFromJSON(subscriptionJSON)
	if err != nil {
		t.Errorf("Failed to parse main sample subscription: %v", err)
	}

	// key and auth values are valid Base64 with or without padding
	_, err = SubscriptionFromJSON([]byte(`{
		"endpoint": "https://example.com",
		"keys": {
			"p256dh": "AAAA",
			"auth": "AAAA"
		}
	}`))
	if err != nil {
		t.Errorf("Failed to parse subscription with 4-character values: %v", err)
	}

	// key and auth values are padded Base64
	_, err = SubscriptionFromJSON([]byte(`{
		"endpoint": "https://example.com",
		"keys": {
			"p256dh": "AA==",
			"auth": "AAA="
		}
	}`))
	if err != nil {
		t.Errorf("Failed to parse subscription with padded values: %v", err)
	}

	// key and auth values are unpadded Base64
	_, err = SubscriptionFromJSON([]byte(`{
		"endpoint": "https://example.com",
		"keys": {
			"p256dh": "AA",
			"auth": "AAA"
		}
	}`))
	if err != nil {
		t.Errorf("Failed to parse subscription with unpadded values: %v", err)
	}
}
