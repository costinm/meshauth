package meshauth

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"log/slog"
)

// mds is the 'metadata service' - running on the node
// or as a sidecar and providing metadata and tokens for local
// workloads.
// ZTunnel will also act as a MDS server.

// The server side emulates a GCP MDS. Client side defaults to an GCP
// style MDS. Other servers may be emulated - but current gRPC libraries
// and envoy use this.

// MDS also supports a 'Subscribe' call: mds.Subscribe(suffix, fn(string, ok).
// based on ?wait_for_change=true&last_etag=ETAG
// Metadata package uses suffix past /v1/ in the interfaces.

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

// MDS represents the workload metadata.
// It is extracted from environment: env variables, mesh config, local metadata server.
type MDS struct {
	// Certificate and client factory.
	MeshAuth *MeshAuth

	// Addr is the address of the MDS server, including http:// or https://
	// Will detect a GCP/GKE server
	Addr string

	// For GCP MDS, request the full token content.
	UseMDSFullToken bool

	Meta sync.Map
}

// Determine the workload name, using environment variables or hostname.
// This should be unique, typically pod-xxx-yyy
func (mds *MDS) WorkloadName() string {
	name := os.Getenv("POD_NAME")
	if name == "" {
		name = os.Getenv("WORKLOAD_NAME")
	}
	if name != "" {
		return name
	}
	ks := os.Getenv("K_SERVICE")
	if ks != "" {
		verNsName := strings.SplitN(ks, "--", 2)
		if len(verNsName) > 1 {
			return verNsName[1]
			//kr.Labels["ver"] = verNsName[0]
		} else {
			return ks
		}
	}
	name, _ = os.Hostname()
	// TODO: split and extract namespace
	return name
}

var (
	singleAudienceError = errors.New("single audience supported")
)

// GetRequestMetadata implements credentials.PerRPCCredentials
// This can be used for both WorkloadID tokens or access tokens - if the 'aud' containts googleapis.com, access tokens are returned.
func (s *MDS) GetRequestMetadata(ctx context.Context, aud ...string) (map[string]string, error) {
	ta := ""
	if len(aud) > 0 {
		ta = aud[0]
	}
	if len(aud) > 1 {
		return nil, singleAudienceError
	}
	t, err := s.GetToken(ctx, ta)
	if err != nil {
		return nil, err
	}
	return ToMeta(t), nil
}

// Get an WorkloadID token from platform (GCP, etc) using metadata server.
//
//	curl  -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=[AUDIENCE]" \
//
// On GKE requires annotation: iam.gke.io/gcp-service-account=[GSA_NAME]@[PROJECT_ID]
// May fail and need retry
func (s *MDS) GetToken(ctx context.Context, aud string) (string, error) {
	uri := fmt.Sprintf("instance/service-accounts/default/identity?audience=%s", aud)
	if s.UseMDSFullToken { // TODO: test the difference
		uri = uri + "&format=full"
	}
	tok, err := s.MetadataGet(uri)
	if err != nil {
		return "", err
	}
	return tok, nil
}

func (s *MDS) RequireTransportSecurity() bool {
	return false
}

func (s *MDS) ProjectID() string {
	pidA, _ := s.Meta.Load(projIDPath)
	if pidA != "" {
		return pidA.(string)
	}

	pid, _ := s.MetadataGet(projIDPath)
	if pid != "" {
		return pid
	}

	pid = os.Getenv("PROJECT_ID")
	if pid != "" {
		return pid
	}

	return ""
}

// GetMDS returns MDS info:
//
// For GCP:
// instance/hostname - node name.c.PROJECT.internal
// instance/attributes/cluster-name, cluster-location
// project/project-id, numeric-project-id
//
// Auth:
// instance/service-accounts/ - default, PROJECTID.svc.id.goog
// instance/service-accounts/default/identity - requires the iam.gke.io/gcp-service-account=gsa@project annotation and IAM
// instance/service-accounts/default/token - access token for the KSA
func (m *MDS) MetadataGet(path string) (string, error) {
	ctx, cf := context.WithTimeout(context.Background(), 3*time.Second)
	defer cf()
	if m.Addr == "" {
		mdsHost := os.Getenv("GCE_METADATA_HOST")
		if mdsHost == "" {
			mdsHost = "169.254.169.254" // or metadata.google.internal
		}
		m.Addr = "http://" + mdsHost + "/computeMetadata/v1"
	}
	mdsHost := m.Addr

	req, err := http.NewRequestWithContext(ctx, "GET", mdsHost+"/"+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server responeded with code=%d %s", resp.StatusCode, resp.Status)
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), err
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
func (m *MDS) HandleMDS(w http.ResponseWriter, r *http.Request) {
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
