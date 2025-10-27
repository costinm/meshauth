package ugcp

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
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

// TokenSource is a common interface for anything returning Bearer or other kind of tokens.
type TokenSource interface {
	// GetToken for a given audience.
	GetToken(context.Context, string) (string, error)
}

type MDSD struct {

	// "gcp" or "gcp_fed" access token providers.
	// Latter is used if no gcp tokens are available, and we exchange a K8S or
	// other token
	GCPTokenProvider TokenSource

	// ID token provider. "gcp" or "k8s" or any other source.
	// Note that gmail accounts can't generate JWT tokens (except the gcloud project,
	// which happens to work with CloudRun). Service Accounts can - and a GSA can
	// allow a google account to get tokens.
	TokenProvider TokenSource

	Metadata Metadata

	Addr string
	Mux *http.ServeMux `json:"-"`
}

func (mdsd *MDSD) Start() error {
	// Start an emulated MDS server if address is set and not running on GCP
	// MDS emulator/redirector listens on localhost by default, as a sidecar or service.
	//
		os.Setenv("GCE_METADATA_HOST", "localhost:15021")

		if mdsd.Mux == nil {
			mdsd.Mux = http.NewServeMux()
			if mdsd.Addr == "" {
				mdsd.Addr = "127.0.0.1:15021"
			}
			go http.ListenAndServe(mdsd.Addr, mdsd.Mux)
		}

	// Emulated MDS server
	mdsd.Mux.HandleFunc("/computeMetadata/v1/", mdsd.HandleMDS)

	// Required for golang detection of GCP MDS - there is no header except user-agent
	mdsd.Mux.HandleFunc("/", func(w http.ResponseWriter, request *http.Request) {
		w.Header().Add("Metadata-Flavor", "Google")
		w.WriteHeader(200)
		log.Println("DefaultCredentials check from", request.RemoteAddr, request.Header)
	})
		return nil
}

func NewServer() *MDSD {
	return &MDSD{}
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
func (mdsd *MDSD) HandleMDS(w http.ResponseWriter, r *http.Request) {
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
		fmt.Fprintf(w, "%s", mdsd.Metadata.Project.ProjectId)
		return
	case projNumberPath:
		w.WriteHeader(200)
		fmt.Fprintf(w, "%d", mdsd.Metadata.Project.NumericProjectId)
		return
	case "machine-type":
		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", "dev")
		return
	case zonePath:
		w.WriteHeader(200)
		fmt.Fprintf(w, "%s", mdsd.Metadata.Instance.Zone)
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
			if mdsd.Metadata.Instance.ServiceAccounts != nil {
				def := ""
				for k, v := range mdsd.Metadata.Instance.ServiceAccounts {
					if k == parts[5] {
						def = v.Email
					}
					if def == "" {
						def = v.Email
					}
				}
				fmt.Fprintf(w, `%s`, def)
			}
		case "token":
			tp := mdsd.GCPTokenProvider // ["gcp"]
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
			tp := mdsd.TokenProvider
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
