package mdsd

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"strings"

	"github.com/costinm/meshauth"
)

const (
	metaPrefix     = "/computeMetadata/v1"
	projIDPath     = metaPrefix + "/project/project-id"
	projNumberPath = metaPrefix + "/project/numeric-project-id"
	instIDPath     = metaPrefix + "/instance/id"
	instancePath   = metaPrefix + "/instance/name"
	zonePath       = metaPrefix + "/instance/zone"
	attrKey        = "attribute"
	attrPath       = metaPrefix + "/instance/attributes/{" + attrKey + "}"

	sshPath  = metaPrefix + "/project/attributes/sshKeys"
	sshPath2 = metaPrefix + "/instance/attributes/ssh-keys"
)

type MDSD struct {
	MeshAuth *meshauth.Mesh
	Metadata Metadata
}



func SetupAgent(ma *meshauth.Mesh, mux *http.ServeMux) error {
	// Auto-detect the environment and mesh certificates, if any.
	// TODO: detect the istio-mounted istio-ca scoped token location and use it as a source.
	// On CloudRun or regular VMs - will not detect anything unless a secret is mounted.

	mdsd := &MDSD{MeshAuth: ma}

	ma.Get("mds", &mdsd.Metadata)
	// Emulated MDS server
	mux.HandleFunc("/computeMetadata/v1/", mdsd.HandleMDS)

	// Required for golang detection of GCP MDS - there is no header except user-agent
	mux.HandleFunc("/", func(w http.ResponseWriter, request *http.Request) {
		w.Header().Add("Metadata-Flavor", "Google")
		w.WriteHeader(200)
		log.Println("DefaultCredentials check from", request.RemoteAddr, request.Header)
	})

	return nil
}


// MDS emulates the GCP metadata server.
// MDS address is 169.254.169.254:80 - can be intercepted with iptables, or
// set using GCE_METADATA_HOST
// https://googleapis.dev/python/google-auth/latest/reference/google.auth.environment_vars.html
// https://pkg.go.dev/cloud.google.com/go/compute/metadata#Client.Get
//
// gRPC library will use it if:
// - the env variable is set
// - a probe to the IP and URL / returns the proper flavor.
// - DNS resolves metadata.google.internal to the IP
func (m *MDSD) HandleMDS(w http.ResponseWriter, r *http.Request) {
	flavor := r.Header.Get("Metadata-Flavor")

	if flavor == "" && r.RequestURI != "/" {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		return
	}

	w.Header().Add("Metadata-Flavor", "Google")

	// TODO: ?recursive=true

	// WIP
	if !strings.HasPrefix(r.URL.Path, metaPrefix) {
		return
	}

	defer func() {
		slog.Info("MDS", "URI", r.URL, "path", r.RequestURI)
	}()

	switch r.RequestURI {
	case projIDPath:
		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", m.Metadata.Project.ProjectId)
		return
	case projNumberPath:
		w.WriteHeader(200)
		fmt.Fprintf(w, "%d", m.Metadata.Project.NumericProjectId)
		return
	case "machine-type":
		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", "dev")
		return
	case zonePath:
		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", m.Metadata.Instance.Zone)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/computeMetadata/v1/instance/service-accounts/") {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) <= 6 {
			w.WriteHeader(500)
			return
		}
		slog.Info("MDS", "URI", r.URL, "path", r.RequestURI,
			"from", r.RemoteAddr, "user", parts[5], "kind", parts[6])

		switch parts[6] {
		case "email":
			w.WriteHeader(200)
			fmt.Fprintf(w, `%s`, m.MeshAuth.GSA)
		case "token":
			tp := m.MeshAuth.AuthProviders["gcp"]
			if tp == nil {
				tp = m.MeshAuth.AuthProviders["gcp_fed"]
			}
			if tp == nil {
				w.WriteHeader(500)
				return
			}
			tok, err := tp.GetToken(context.Background(), "")
			if err != nil {
				slog.Warn("MDSTokenError", "err", err)
				w.WriteHeader(500)
				return
			}
			w.WriteHeader(200)
			fmt.Fprintf(w, `{"access_token": "%s","expires_in":3599,"token_type":"Bearer"}`, tok)
		case "identity":
			aud := r.URL.Query()["audience"]
			tp := m.MeshAuth.AuthProviders["gcp"]
			if tp == nil {
				tp = m.MeshAuth.AuthProviders["k8s"]
				slog.Warn("No GCP provider, using K8S TokenRequest", "aud", aud)
			}
			if tp == nil {
				w.WriteHeader(500)
				return
			}

			tok, err := tp.GetToken(context.Background(), aud[0])
			if err != nil {
				slog.Warn("MDSTokenError", "err", err, "aud", aud)
				w.WriteHeader(500)
				return
			}
			w.WriteHeader(200)
			fmt.Fprintf(w, "%s", tok)
		default:
			w.WriteHeader(500)
		}

		// Envoy request: Metadata-Flavor:[Google] X-Envoy-Expected-Rq-Timeout-Ms:[1000] X-Envoy-Internal:[true]
	}

	w.WriteHeader(404)

}
