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
	"encoding/base64"
	"encoding/hex"
	"log"
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
	sub := &Dest{
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

func xTestWebpush(t *testing.T) {
	//POST /push/JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV HTTP/1.1
	// Host: push.example.net
	//TTL: 10
	// Content-Length: 33
	// Content-Encoding: aes128gcm

	auths := "BTBZMqHH6r4Tts7J_aSIgg"
	authB, _ := base64.RawURLEncoding.DecodeString(auths)
	rpriv := "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"
	rpub := "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
	rv := NewMeshAuth(&MeshCfg{EC256Pub: rpub, EC256Key: rpriv})

	spriv := "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
	spub := "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
	sv := NewMeshAuth(&MeshCfg{EC256Pub: spub, EC256Key: spriv})

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
	ec.SendPrivate = sv.ec256Priv
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
