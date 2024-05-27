package agent

import (
	"context"

	"github.com/costinm/meshauth"

	"log"
	"net/http"
)

type Config struct {
	meshauth.MeshCfg `json:inline`

	MainMux *http.ServeMux `json:-`
}

var stop = make(chan struct{})

func SetupAgent(ctx context.Context, maCfg *meshauth.MeshCfg, k meshauth.TokenSource,
	mux *http.ServeMux) (*meshauth.MeshAuth, error) {
	// Auto-detect the environment and mesh certificates, if any.
	// TODO: detect the istio-mounted istio-ca scoped token location and use it as a source.
	// On CloudRun or regular VMs - will not detect anything unless a secret is mounted.
	ma, err := meshauth.FromEnv(maCfg)
	if err != nil {
		return nil, err
	}

	ma.AuthProviders["k8s"] = k

	fedS := meshauth.NewFederatedTokenSource(&meshauth.STSAuthConfig{
		AudienceSource: ma.ProjectID + ".svc.id.goog",
		TokenSource:    k,
	})
	// Federated access tokens (for ${PROJECT_ID}.svc.id.goog[ns/ksa]
	// K8S JWT access tokens otherwise.
	ma.AuthProviders["gcp_fed"] = fedS

	if ma.GSA == "" {
		// Use default naming conventions
		ma.GSA = "k8s-" + maCfg.Namespace + "@" + maCfg.ProjectID + ".iam.gserviceaccount.com"
	}

	if ma.GSA != "-" {
		audTokenS := meshauth.NewFederatedTokenSource(&meshauth.STSAuthConfig{
			TokenSource:    k,
			GSA:            ma.GSA,
			AudienceSource: ma.ProjectID + ".svc.id.goog",
		})
		ma.AuthProviders["gcp"] = audTokenS
	}

	// Emulated MDS server
	mux.HandleFunc("/computeMetadata/v1/", ma.MDS.HandleMDS)

	// Required for golang detection of GCP MDS - there is no header except user-agent
	mux.HandleFunc("/", func(w http.ResponseWriter, request *http.Request) {
		w.Header().Add("Metadata-Flavor", "Google")
		w.WriteHeader(200)
		log.Println("DefaultCredentials check from", request.RemoteAddr)
	})

	return ma, nil
}
