package main

import (
	"context"
	"log"
	"net/http"

	"golang.org/x/exp/slog"
	"sigs.k8s.io/yaml"

	"github.com/costinm/meshauth"
)

// Meshauth  can run on a local dev machine, in a docker container or in K8S. Will emulate a MDS
// server and can maintain tokens, certificates and auxiliary mesh configs.
func main() {
	ctx := context.Background()

	// Load the main and all secondary k8s clusters
	main, all, err := meshauth.KubeFromEnv(func(bytes []byte, i interface{}) error {
		return yaml.Unmarshal(bytes, i)
	})
	if err != nil {
		log.Fatal(err)
	}

	if main != nil {
		slog.InfoCtx(ctx, "K8S cluster", "name", main.ClusterName, "kc", main)
	}

	for cn, kc := range all {
		if kc == main {
			continue
		}
		slog.InfoCtx(ctx, "Secondary K8S cluster", "name", cn, "kc", kc)
	}

	var ma *meshauth.MeshAuth
	// Operate in normal per-node or local mode
	// Auto-detect the environment and setup mesh certificates.
	ma, err = meshauth.FromEnv(nil)
	if err != nil {
		log.Fatal(err)
	}

	// If certificate is not found, we need to get it
	// TODO:

	slog.InfoCtx(ctx, "CA root")
	log.Println(ma.CertDir)

	// Proxy for MDS
	http.Handle("/computeMetadata/v1/", ma.MDS)

	//
	sts := meshauth.NewFederatedTokenSource(&meshauth.STSAuthConfig{})
	http.Handle("/sts/", sts)

	select {}
}
