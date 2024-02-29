package mdsd

import (
	"context"
	"fmt"
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
	Meta     *meshauth.Metadata
	MeshAuth *meshauth.MeshAuth
	ByIP     map[string]*meshauth.Metadata
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
func (m *MDSD) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	if strings.HasPrefix(r.URL.Path, "/computeMetadata/v1/instance/service-accounts/") {
		slog.Info("MDS", "URI", r.URL, "path", r.RequestURI,
			"from", r.RemoteAddr)
		parts := strings.Split(r.URL.Path, "/")

		isEmail := len(parts) > 6 && parts[6] == "email"
		if isEmail {
			w.WriteHeader(200)
			fmt.Fprintf(w, `%s`, m.MeshAuth.GSA)
			return
		}
		isToken := len(parts) > 6 && parts[6] == "token"
		if isToken {
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
			return
		}

		aud := r.URL.Query()["audience"]
		if len(parts) <= 6 || parts[6] != "identity" || len(aud) == 0 {
			w.WriteHeader(500)
			return
		}
		// ID token request

		// Envoy request: Metadata-Flavor:[Google] X-Envoy-Expected-Rq-Timeout-Ms:[1000] X-Envoy-Internal:[true]

		tp := m.MeshAuth.AuthProviders["gcp"]
		if tp == nil {
			tp = m.MeshAuth.AuthProviders["k8s"]
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
	}

	switch r.RequestURI {
	case projIDPath:
		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", m.MeshAuth.MeshCfg.MDS.Project.ProjectId)
	case projNumberPath:
		w.WriteHeader(200)
		fmt.Fprintf(w, "%d", m.MeshAuth.MeshCfg.MDS.Project.NumericProjectId)
	case "machine-type":
		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", "dev")
	case zonePath:

		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", "us-central1")
	}
}
