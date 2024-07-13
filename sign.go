package meshauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
)

func VerifyKey(alg string, txt []byte, pk crypto.PublicKey, sig []byte) error {
	hasher := crypto.SHA256.New()
	hasher.Write(txt)

	if alg == "ES256" {
		r := big.NewInt(0).SetBytes(sig[0:32])
		s := big.NewInt(0).SetBytes(sig[32:64])
		match := ecdsa.Verify(pk.(*ecdsa.PublicKey), hasher.Sum(nil), r, s)
		if !match {
			return  errors.New("invalid ES256 signature")
		}
		return nil
	} else if alg == "EdDSA" {
		ok := ed25519.Verify(pk.(ed25519.PublicKey), hasher.Sum(nil), sig)
		if !ok {
			return errors.New("invalid ED25519 signature")
		}

	} else if alg == "RS256" {
		rsak := pk.(*rsa.PublicKey)
		hashed := hasher.Sum(nil)
		err := rsa.VerifyPKCS1v15(rsak, crypto.SHA256, hashed, sig)
		if err != nil {
			return err
		}
		return  nil
	}
	return  errors.New("Unsupported " + alg)
}

// Verify checks the data is signed with the public key
// pub can be a 64 byte EC256 or 32 byte ED25519
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


func Sign(data []byte, p crypto.PrivateKey) []byte {

	hasher := crypto.SHA256.New()
	hasher.Write(data)

	return SignHash(hasher.Sum(nil), p)
}

func SignHash(data []byte, p crypto.PrivateKey) []byte {
	var sig []byte
	if ec, ok := p.(*ecdsa.PrivateKey); ok {
		if r, s, err := ecdsa.Sign(rand.Reader, ec,data ); err == nil {
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
	} else if ed, ok := p.(ed25519.PrivateKey); ok {
		sig, _ = ed.Sign(rand.Reader, data, nil)
	}

	return sig
}
