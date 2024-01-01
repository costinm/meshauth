package main

import (
	"context"
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
	"sigs.k8s.io/yaml"
)

var (
	aud   = flag.String("aud", "", "Audience, if empty, the k8s default token is returned")
	gcpSA = flag.String("gsa", "", "Google service account to impersonate")

	fed = flag.Bool("fed", false, "Return the federated token")

	namespace = flag.String("n", "", "Namespace")
	ksa       = flag.String("ksa", "default", "kubernetes service account")

	certDir = flag.String("outCertDir", ".", "Directory to save workload certificates.")

	decode = flag.String("d", "", "Decode token")
)

func init() {
	meshauth.YAMLUnmarshal = func(bytes []byte, i interface{}) error {
		return yaml.Unmarshal(bytes, i)
	}
}

// Decode a JWT.
// If crt is specified - verify it using that cert
func decodeJWT(jwt, aud string) {
	// TODO: verify if it's a VAPID
	parts := strings.Split(jwt, ".")
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

	h, t, txt, sig, _ := meshauth.JwtRawParse(jwt)
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

func main() {
	flag.Parse()

	cmd := flag.Arg(0)
	if cmd == "initCA" {
		caDir := os.Getenv("CA_DIR")
		if caDir == "" {
			caDir = "."
		}
		// Operate in CA root mode
		ca := meshauth.CAFromEnv(caDir)
		if ca.Private == nil {
			ca.NewRoot()
			ca.Save(caDir)
		}

		return
	}

	if *decode != "" {
		fmt.Println(meshauth.TokenPayload(*decode))
		return
	}

	home, _ := os.UserHomeDir()

	if *certDir != "" {
		// Root CA stored in user home, next to .ssh keys
		ca := meshauth.CAFromEnv(filepath.Join(home, ".ssh"))

		// Create a new mesh identity from the CA.
		meshid := ca.NewID(*namespace, *ksa, nil)

		meshid.SaveCerts(*certDir)
		return
	}

	ctx := context.Background()
	def, _, err := meshauth.KubeFromEnv()
	if err != nil {
		log.Fatal("Can't load kube config file")
	}

	var tokenProvider meshauth.TokenSource

	if *fed {
		tokenProvider, err = def.GCPFederatedSource(ctx)
	} else if *gcpSA == "" {
		tokenProvider = def // .NewK8STokenSource(*aud)
	} else {
		gsa := *gcpSA
		if *gcpSA == "default" {
			gsa = ""
		}
		tokenProvider, err = meshauth.GCPAccessTokenSource(def, gsa)
	}
	if err != nil {
		log.Fatal("Failed to get token", err)
	}

	t, err := tokenProvider.GetToken(ctx, *aud)
	if err != nil {
		log.Fatal("Failed to get token", err)
	}
	fmt.Println(t)
}
