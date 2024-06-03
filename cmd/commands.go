package cmd

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/costinm/meshauth"
)

var (
	aud   = flag.String("aud", "", "Audience, if empty, the k8s default token is returned")


	namespace = flag.String("n", "", "Namespace")
	ksa       = flag.String("ksa", "default", "kubernetes service account")

	certDir = flag.String("outCertDir", ".", "Directory to save workload certificates.")

	decode = flag.String("jwt", "", "JWT token")
)


var Commands = map[string]func() {
	"decode": decodeJWT,
}

func DecodeJWT() {
	fmt.Println(meshauth.TokenPayload(*decode))
}

func InitCA() {
	caDir := os.Getenv("CA_DIR")
	if caDir == "" {
		caDir = "."
	}
	// Operate in CA root mode
	ca := meshauth.NewCA(&meshauth.CAConfig{RootLocation: caDir})
	if ca.Private == nil {
		ca.NewRoot()
		ca.Save(caDir)
	}
}

func NewID() {
	home, _ := os.UserHomeDir()

	// Root CA stored in user home, next to .ssh keys
	ca := meshauth.NewCA(&meshauth.CAConfig{RootLocation: filepath.Join(home, ".ssh")})

	// Create a new mesh identity from the CA.
	meshid := ca.NewID(*namespace, *ksa, nil)

	meshid.SaveCerts(".")
}


// Decode a JWT.
// If crt is specified - verify it using that cert
func decodeJWT() {
	// TODO: verify if it's a VAPID
	parts := strings.Split(*decode, ".")
	p1b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println(string(p1b))

	scrt, _ := ioutil.ReadFile("server.crt")
	block, _ := pem.Decode(scrt)
	xc, _ := x509.ParseCertificate(block.Bytes)
	log.Printf("Cert subject: %#v\n", xc.Subject)
	pubk1 := xc.PublicKey

	h, t, txt, sig, _ := meshauth.JwtRawParse(*decode)
	log.Printf("%#v %#v\n", h, t)

	if h.Alg == "RS256" {
		rsak := pubk1.(*rsa.PublicKey)
		hasher := crypto.SHA256.New()
		hasher.Write(txt)
		hashed := hasher.Sum(nil)
		err = rsa.VerifyPKCS1v15(rsak, crypto.SHA256, hashed, sig)
		if err != nil {
			log.Println("Root Certificate not a signer")
		}
	}

}
