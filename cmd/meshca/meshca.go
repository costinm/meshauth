package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/costinm/meshauth"
	"golang.org/x/exp/slog"
)

// Meshca  can run on a local dev machine, in a docker container or in K8S.
// It can  acts as a minimal CA or a CA proxy (forwarding to a delegated CA).
//
// The root CA should be mounted on /var/run/secrets/cacerts/ or ${HOME}/.ssh
func main() {
	ctx := context.Background()

	var ma *meshauth.MeshAuth
	caDir := os.Getenv("CA_DIR")
	if caDir != "" {
		// Operate in CA root mode
		ca := meshauth.CAFromEnv(caDir)
		ma = ca.NewID("istio-system", "istiod")
	}

	slog.InfoCtx(ctx, "CA root")
	log.Println(ma.CertDir)

	// TODO: Provide a cluster STS service - exchanging K8S root JWTs with GSA (if permission is granted
	// to the CA SA to impersonate the GSA). The names of the GSA are hardcoded as:
	// k8s-CLUSTER-NAMESPACE-KSA

	http.HandleFunc("/.well-known/openid-configuration", ma.HandleDisc)
	http.HandleFunc("/.well-known/jwks", ma.HandleJWK)

	// TODO: Also load the echo client

	select {}
}
