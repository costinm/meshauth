package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/costinm/meshauth"
	"sigs.k8s.io/yaml"
)

var (
	aud   = flag.String("aud", "", "Audience, if empty, the k8s default token is returned")
	gcpSA = flag.String("gsa", "", "Google service account to impersonate")

	fed = flag.Bool("fed", false, "Return the federated token")

	namespace = flag.String("n", "", "Namespace")
)

func main() {
	flag.Parse()
	kconf, err := LoadKubeconfig()
	if err != nil {
		log.Fatal("Can't load kube config file")
	}

	ctx := context.Background()
	def, _, err := meshauth.InitK8S(ctx, kconf)

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
		tokenProvider, err = def.GCPAccessTokenSource(gsa)
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

func LoadKubeconfig() (*meshauth.KubeConfig, error) {
	kc := os.Getenv("KUBECONFIG")
	if kc == "" {
		kc = os.Getenv("HOME") + "/.kube/config"
	}
	kconf := &meshauth.KubeConfig{}

	var kcd []byte
	if kc != "" {
		if _, err := os.Stat(kc); err == nil {
			// Explicit kube config, using it.
			// 	"sigs.k8s.io/yaml"
			kcd, err = ioutil.ReadFile(kc)
			if err != nil {
				return nil, err
			}
			err := yaml.Unmarshal(kcd, kconf)
			if err != nil {
				return nil, err
			}

			return kconf, nil
		}
	}
	return nil, nil
}
