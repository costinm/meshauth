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
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"testing"
	"time"

	"github.com/costinm/meshauth"
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
	message = `I am the walrus`

	rfcPlaintext = "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24"
	rfcAsPublic  = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
	rfcAsPrivate = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
	rfcUAPublic  = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
	rfcUAPrivate = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"

	rfcCipher = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN" //"8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ"//"6nqAQUME8hNqw5J3kl8cpVVJylXKYqZOeseZG8UueKpA"
	rfcSalt   = "DGv6ra1nlYgDCS1FRnbzlw"
	rfcAuth   = "BTBZMqHH6r4Tts7J_aSIgg"
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
	serverPrivateKey, _, _ := randomKey()
	invalidPub, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	_, err := sharedSecret(curve, invalidPub, serverPrivateKey)
	if err == nil {
		t.Error("Expected an error due to invalid public key")
	}
	_, err = sharedSecret(curve, nil, serverPrivateKey)
	if err == nil {
		t.Error("Expected an error due to nil key")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	sub, _ := WebpushSubscriptionToDest(subscriptionJSON)
	for i := 0; i < b.N; i++ {
		Encrypt(sub.WebpushPublicKey, sub.WebpushAuth, "Hello world")
	}
}

func TestEncrypt(t *testing.T) {
	sub, _ := WebpushSubscriptionToDest(subscriptionJSON)
	_, err := Encrypt(sub.WebpushPublicKey, sub.WebpushAuth, "Hello world")
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
	auth, err := b64.DecodeString("68zcbmaevQa7MS7aXXRX8Q")
	sub := &meshauth.Dest{
		Addr:             "https://foo.com",
		WebpushAuth:      auth,
		WebpushPublicKey: subPub,
	}
	result, err := Encrypt(sub.WebpushPublicKey, sub.WebpushAuth, message)
	if err != nil {
		t.Error(err)
	}

	dc := WebpushEncryption{
		UAPrivate: subPriv,
		UAPublic:  subPub,
		Auth:      auth,
	}
	plain, err := dc.Decrypt(result.Ciphertext)

	// assumes 2-bytes padding length == 0
	if err != nil {
		t.Error("Decrypt error ", err)
	} else if string(plain) != message {
		t.Error(plain, message)
		return
	}
}

func TestWebpush(t *testing.T) {
	//POST /push/JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV HTTP/1.1
	// Host: push.example.net
	//TTL: 10
	// Content-Length: 33
	// Content-Encoding: aes128gcm

	auths := "BTBZMqHH6r4Tts7J_aSIgg"
	authB, _ := base64.RawURLEncoding.DecodeString(auths)
	rpriv := "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"
	//rpub := "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
	rv := meshauth.New(nil)
	rv.InitSelfSignedKey(rpriv)

	spriv := "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
	spub := "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
	sv := meshauth.New(&meshauth.MeshCfg{EC256Pub: spub, EC256Key: spriv})
	sv.InitSelfSignedKeyRaw(meshauth.RawKeyToPrivateKey(spriv, spub))
	wp := New(sv)

	plain := "When I grow up, I want to be a watermelon"

	salt := "DGv6ra1nlYgDCS1FRnbzlw"
	saltB, _ := base64.RawURLEncoding.DecodeString(salt)

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

	body := "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
	bodyB, _ := base64.RawURLEncoding.DecodeString(body)

	ec := NewWebpushEncryption(rv.PublicKey, authB)
	// To reproduce the same output, use the key from the RFC.
	ec.SendPrivate = wp.EC256Priv
	ec.SendPublic = sv.PublicKey
	ec.Salt = saltB

	cipher, err := ec.Encrypt([]byte(plain))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(cipher, bodyB) {
		t.Error("Failed to encrypt")
	}

	dc := NewWebpushDecryption(rv.EC256Key, rv.PublicKey, authB)
	plain1, err := dc.Decrypt(cipher)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plain1, []byte(plain)) {
		t.Error("Failed to decrypt")
	}

	ec1 := NewWebpushEncryption(rv.PublicKey, authB)
	cipher, _ = ec1.Encrypt([]byte{1})
	if len(cipher) != 104 {
		t.Error("One byte expecting 104 got ", len(cipher))
	}
	log.Printf("Encrypt 1 byte to %d", len(cipher))

	ec2 := NewWebpushDecryption(rv.EC256Key, rv.PublicKey, authB)
	plainB, err := ec2.Decrypt(cipher)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plainB, []byte{1}) {
		t.Error("Failed to decrypt")
	}
}

// ========== Old VAPID JWT tests =============

const (
	testpriv = "bSaKOws92sj2DdULvWSRN3O03a5vIkYW72dDJ_TIFyo"
	testpub  = "BALVohWt4pyr2L9iAKpJig2mJ1RAC1qs5CGLx4Qydq0rfwNblZ5IJ5hAC6-JiCZtwZHhBlQyNrvmV065lSxaCOc"
)


var Curve256 = elliptic.P256()

// ~31us on amd64/2G
func BenchmarkSig(b *testing.B) {
	pubb, _ := base64.RawURLEncoding.DecodeString(testpub)
	priv, _ := base64.RawURLEncoding.DecodeString(testpriv)
	d := new(big.Int).SetBytes(priv)
	x, y := elliptic.Unmarshal(Curve256, pubb)
	pubkey := ecdsa.PublicKey{Curve: Curve256, X: x, Y: y}
	pkey := ecdsa.PrivateKey{PublicKey: pubkey, D: d}

	for i := 0; i < b.N; i++ {
		hasher := crypto.SHA256.New()
		hasher.Write(pubb[1:65])
		ecdsa.Sign(rand.Reader, &pkey, hasher.Sum(nil))
	}
}

// 2us
func BenchmarkVerify(b *testing.B) {
	pubb, _ := base64.RawURLEncoding.DecodeString(testpub)
	priv, _ := base64.RawURLEncoding.DecodeString(testpriv)
	d := new(big.Int).SetBytes(priv)
	x, y := elliptic.Unmarshal(Curve256, pubb)
	pubkey := ecdsa.PublicKey{Curve: Curve256, X: x, Y: y}
	pkey := ecdsa.PrivateKey{PublicKey: pubkey, D: d}
	hasher := crypto.SHA256.New()
	hasher.Write(pubb[1:65])
	r, s, _ := ecdsa.Sign(rand.Reader, &pkey, hasher.Sum(nil))
	rBytes := r.Bytes()
	rBytesPadded := make([]byte, 32)
	copy(rBytesPadded[32-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, 32)
	copy(sBytesPadded[32-len(sBytes):], sBytes)
	sig := append(rBytesPadded, sBytesPadded...)

	for i := 0; i < b.N; i++ {
		meshauth.Verify(pubb, pubb, sig)
	}
}




func TestVapid(t *testing.T) {
	rfcEx := "vapid t=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3B1c2guZXhhbXBsZS5uZXQiLCJleHAiOjE0NTM1MjM3NjgsInN1YiI6Im1haWx0bzpwdXNoQGV4YW1wbGUuY29tIn0.i3CYb7t4xfxCDquptFOepC9GAu_HLGkMlMuCGSK2rpiUfnK9ojFwDXb1JrErtmysazNjjvW2L9OkSSHzvoD1oA, " +
			"k=BA1Hxzyi1RUM1b5wjxsn7nGxAszw2u61m164i3MrAIxHF6YK5h4SDYic-dRuU_RCPCfA5aq9ojSwk5Y2EmClBPs"

	rfcT, rfcP, err := CheckVAPID(rfcEx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range rfcT.Aud {
		if a != "https://push.example.net" {
			t.Fatal("Aud got ", rfcT.Aud)
		}
	}
	log.Println(len(rfcP), rfcT)

	alice := meshauth.New(&meshauth.MeshCfg{
		Domain: "test.sender"}).InitSelfSigned("")
	av := New(alice)

	bobToken, _ := av.GetToken(context.Background(), "bob")
	log.Println("Authorization: " + bobToken)

	tok, pub, err := CheckVAPID(bobToken, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	log.Println(len(pub), tok)

	btb := []byte(bobToken)
	btb[50]++
	bobToken = string(btb)
	_, _, err = CheckVAPID(bobToken, time.Now())
	if err == nil {
		t.Fatal("Expecting error")
	}

}

func TestSigFail(t *testing.T) {
	payload := `{"UA":"22-palman-LG-V510-","IP4":"10.1.10.223"}`
	log.Println(payload)

	payloadhex, _ := hex.DecodeString("7b225541223a2232322d70616c6d616e2d4c472d563531302d222c22495034223a2231302e312e31302e323233227d0a9d4eda35ad1bba104bfee8f92c3d602ceb6f53754a499e28d5569c5a7173b2c100f9a1d4d19f1154cf2699df676fcd63ddd3bf6cd5e1a4db9bccceec262c0be1")
	log.Println(string(payloadhex[0 : len(payloadhex)-64]))

	//BJ1O2jWtG7oQS/7o+Sw9YCzrb1N1SkmeKNVWnFpxc7LBAPmh1NGfEVTPJpnfZ2/NY93Tv2zV4aTbm8zO7CYsC+E=
	log.Println("Pub:", hex.EncodeToString(payloadhex[len(payloadhex)-64:]))
	log.Println("Pub:", "9d4eda35ad1bba104bfee8f92c3d602ceb6f53754a499e28d5569c5a7173b2c100f9a1d4d19f1154cf2699df676fcd63ddd3bf6cd5e1a4db9bccceec262c0be1")
	//buf := bytes.RBuffer{}
	//buf.Write(payloadhex)
	//buf.Write(pub)

	hasher := crypto.SHA256.New()
	hasher.Write(payloadhex) //[0:64]) // only public key, for debug
	hash := hasher.Sum(nil)
	log.Println("SHA:", hex.EncodeToString(hash))

	sha := "a2fe666ae95fe8b7c05bfb0215c9d58fe2121ec0baef70de8cc5fd10d15a3e9c"
	log.Println("SHA:", sha)

	sig, _ := hex.DecodeString("9930116d656c7b977a46ca948eb7c49f0fe9b4fe11ae3790bbd8ed47d71135278ddda2d3f9b1aafdad08a14e38b5fc71e41527b0aecda7ce307ef23a8f0f8ee1")

	ok := meshauth.Verify(payloadhex, payloadhex[len(payloadhex)-64:], sig)
	log.Println(ok)

}

func TestSig(t *testing.T) {
	pubb, _ := base64.RawURLEncoding.DecodeString(testpub)
	priv, _ := base64.RawURLEncoding.DecodeString(testpriv)
	d := new(big.Int).SetBytes(priv)

	log.Println("Pub: ", hex.EncodeToString(pubb))
	x, y := elliptic.Unmarshal(Curve256, pubb)
	pubkey := ecdsa.PublicKey{Curve: Curve256, X: x, Y: y}

	pkey := ecdsa.PrivateKey{PublicKey: pubkey, D: d}

	hasher := crypto.SHA256.New()
	hasher.Write(pubb[1:65])
	hash := hasher.Sum(nil)
	log.Println("HASH: ", hex.EncodeToString(hash))

	r, s, _ := ecdsa.Sign(rand.Reader, &pkey, hash)
	rBytes := r.Bytes()
	rBytesPadded := make([]byte, 32)
	copy(rBytesPadded[32-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, 32)
	copy(sBytesPadded[32-len(sBytes):], sBytes)
	sig := append(rBytesPadded, sBytesPadded...)

	log.Println(pubkey)

	log.Println("R:", hex.EncodeToString(r.Bytes()), hex.EncodeToString(s.Bytes()))

	err := meshauth.Verify(pubb[1:65], pubb[1:65], sig)
	if err != nil {
		t.Error(err)
	}
}


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

	privkeySub, err := base64.RawURLEncoding.DecodeString("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94")
	if err != nil {
		t.Fatal(err)
	}
	uaPublic, err := base64.RawURLEncoding.DecodeString("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4")
	if err != nil {
		t.Fatal(err)
	}
	authSecret, err := base64.RawURLEncoding.DecodeString("BTBZMqHH6r4Tts7J_aSIgg")
	if err != nil {
		t.Fatal(err)
	}
	//rpriv := "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"
	//rpub := "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"

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

		dc := NewWebpushDecryption(string(privkeySub), uaPublic, authSecret)

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
	vapid := meshauth.New(nil).InitSelfSigned("")
	wp := New(vapid)
	pushReq, err := wp.NewRequest(ts.URL+"/push/", uaPublic,
		authSecret, message, 0, vapid)
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

	vapid := meshauth.New(nil).InitSelfSigned("")
	wp := New(vapid)
	pushReq, err := wp.NewRequest(ts.URL+"/push/", nil, nil, "", 0, vapid)
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
