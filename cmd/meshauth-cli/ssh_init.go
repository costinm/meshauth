package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	gossh "golang.org/x/crypto/ssh"
)

// SetCert or generate a SSH node config.
// To simplify the code and testing, the SSH node will only interact with a config - which
// can be loaded from JSON file or an MDS server, to bootstrap.

func SaveKeyPair(name string) (*ecdsa.PrivateKey, error) {
	privk1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	ecb, _ := x509.MarshalECPrivateKey(privk1)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecb})

	err := ioutil.WriteFile(name, keyPEM, 0700)
	if err != nil {
		return nil, err
	}

	casigner1, _ := gossh.NewSignerFromKey(privk1)
	pubString := string(gossh.MarshalAuthorizedKey(casigner1.PublicKey()))
	err = ioutil.WriteFile(name+".pub", []byte(pubString), 0700)
	if err != nil {
		return nil, err
	}

	return privk1, nil
}
