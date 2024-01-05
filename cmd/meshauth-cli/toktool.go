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

	k8sc "github.com/costinm/mk8s/k8s"

	"github.com/costinm/meshauth"
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
	k := k8sc.NewK8S(&k8sc.K8SConfig{
		Namespace: *namespace,
		KSA:       *ksa,
	})
	err := k.InitK8SClient(ctx)

	def := k.Default
	if err != nil {
		log.Fatal("Can't load kube config file")
	}
	projectID, _, _ := def.GcpInfo()

	var tokenProvider meshauth.TokenSource

	if *fed {
		tokenProvider = meshauth.NewFederatedTokenSource(&meshauth.STSAuthConfig{
			AudienceSource: projectID + ".svc.id.goog",
			TokenSource:    def,
		})
	} else if *gcpSA == "" {
		tokenProvider = def // .NewK8STokenSource(*aud)
	} else {
		gsa := *gcpSA
		if *gcpSA == "default" {
			gsa = ""
		}
		tokenProvider = meshauth.NewFederatedTokenSource(&meshauth.STSAuthConfig{
			AudienceSource: projectID + ".svc.id.goog",
			TokenSource:    def,
			GSA:            gsa,
		})
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
