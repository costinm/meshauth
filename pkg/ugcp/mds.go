package ugcp

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/costinm/meshauth/pkg/xnet"
)

// mds is the 'metadata service' - running on the node or as a
// sidecar or even separate service (with ambient/secure net)
// and providing metadata and tokens for local workloads. This
// is the client side.

// The server side emulates a GCP MDS. Client side defaults to an GCP
// style MDS. Other servers may be emulated - but current gRPC libraries
// and envoy use this protocol, so it is simpler to treat it as
// a standard.
// Google metadata package OnGCE will probe the MDS server, checking the env
// variable first. It will also resolve metadata.google.internal. - but check
// if it is set to metadataIP, so iptables or env variable are required.
// https://cloud.google.com/compute/docs/metadata/querying-metadata


// MDS also supports a 'Subscribe' call: mds.Subscribe(suffix, fn(string, ok).
// based on ?wait_for_change=true&last_etag=ETAG

// Metadata represents info about an instance, as reported by the GCP MDS.
//
// Some info is only available on VMs or CloudRun.
//
type Metadata struct {

	Instance struct {
		Attributes struct {
			// Only GKE
			ClusterLocation string
			ClusterName     string
			ClusterUid      string

			// Only GCP
			// Full authorized_hosts with \n separators
			SSHKeys string
		}

		// Only GCP
		// cpuPlatform
		// description
		// disks
		// guestAttributes
		// image
		// licences
		// machineType projects/NUMBER/machineTypes/NAME
		// maintenanceEvent

		//     "hostname": "gke-CLUSTER_NAME-pool-1-1b6cad60-1l3a.c.costin-asm1.internal",
		// This is the FQDN hostname of the node !
		Hostname string

		ID       int

		// Local part of the hostname.
		Name string

		Zone string

		// Default is present and the service account running the node/VM
		ServiceAccounts map[string]struct {
			Aliases []string // "default"
			Email   string   // Based on annotation on the KSA
			Scopes  []string
		}

		NetworkInterfaces map[string]struct {
			IPV6s string

			// Only GCP
			AccessConfigs struct {
				ExternalIP string
				Type       string // ONE_TO_ONE_NAT
			}
			Gateway           string
			IP                string
			Mac               string
			Mtu               string
			Network           string // projects/NUMBER/network/NAME
			Subnetmask        string
			TargetInstanceIps []string
			DNSServers        []string
		}
		Tags []string
	}

	Project struct {
		NumericProjectId int
		ProjectId        string

		// Only on GCP VMs
		Attributes map[string]string
		// 	SSHKeys2 string

		SSHKeys string `json:"sshKeys"`
	}
}

// MDS represents the workload metadata.
// It is extracted from environment: env variables, mesh config,
// local metadata server. It implements the TokenSource interface,
// by default it should return tokens signed by platform (google) CA
// including access tokens.
type MDS struct {

	// Addr is the address of the MDS server, including http:// or https://
	// Will detect a GCP/GKE server
	Addr string `json:"addr,omitempty"`

	// TODO: use MeshAuth to return a client, may talk with a remote server over mTLS.
	// There is no reason for MDS to be local and plain text.
	hc   *http.Client

	meta *Metadata
}

func New() *MDS {
	return &MDS{
		hc: http.DefaultClient,
		meta: &Metadata{},
	}
}

func (m *MDS) Provision(ctx context.Context) error {
	if m.Addr == "" {
		m.Addr = os.Getenv("GCE_METADATA_HOST")
	}
	if m.Addr == "" {
		m.Addr = "169.254.169.254"
	}
	if !strings.Contains(m.Addr, "/") {
		m.Addr = "http://" + m.Addr + "/computeMetadata/v1/"
	}

	return nil
}


// Get an WorkloadID token from platform (GCP, etc) using metadata server.
//
//	curl  -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=[AUDIENCE]" \
//
// On GKE requires annotation: iam.gke.io/gcp-service-account=[GSA_NAME]@[PROJECT_ID]
// May fail and need retry
//
//
func (s *MDS) GetToken(ctx context.Context, aud string) (string, error) {
	if aud == "" || strings.Contains(aud, "googleapis.com") {
		uri := "instance/service-accounts/default/token"
		tok, err := s.MetadataGet(uri)
		if err != nil {
			return "", err
		}
		return tok, nil
	}

	uri := fmt.Sprintf("instance/service-accounts/default/identity?audience=%s", aud)
	//if s.UseMDSFullToken { // TODO: test the difference
		uri = uri + "&format=full"
	//}
	tok, err := s.MetadataGet(uri)
	if err != nil {
		return "", err
	}
	return tok, nil
}

func (s *MDS) ProjectID() string {
	if s.meta != nil {
		return s.meta.Project.ProjectId
	}
	pid := os.Getenv("PROJECT_ID")
	if pid != "" {
		return pid
	}

	pid, _ = s.MetadataGet(projIDPath)
	if pid != "" {
		return pid
	}

	return ""
}

func (s *MDS) NumericProjectID() string {
	if s.meta.Project.NumericProjectId > 0 {
		return strconv.Itoa(s.meta.Project.NumericProjectId)
	}
	pid := os.Getenv("PROJECT_NUMBER")
	if pid == "" {
		pid, _ = s.MetadataGet(projNumberPath)
	}

	return pid
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

	mdsHost := m.Addr

	req, err := http.NewRequestWithContext(ctx, "GET", mdsHost+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := m.hc.Do(req)
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


// Subscribe subscribes to a value from the metadata service.
// The suffix is appended to "http://${GCE_METADATA_HOST}/computeMetadata/v1/".
// The suffix may contain query parameters.
//
// Subscribe calls fn with the latest metadata value indicated by the provided
// suffix. If the metadata value is deleted, fn is called with the empty string
// and ok false. Subscribe blocks until fn returns a non-nil error or the value
// is deleted. Subscribe returns the error value returned from the last call to
// fn, which may be nil when ok == false.
func (c *MDS) Subscribe(suffix string, fn func(v string, ok bool) error) error {
	const failedSubscribeSleep = time.Second * 5

	// First check to see if the metadata value exists at all.
	val, lastETag, err := c.getETag(suffix)
	if err != nil {
		return err
	}

	if err := fn(val, true); err != nil {
		return err
	}

	ok := true
	if strings.ContainsRune(suffix, '?') {
		suffix += "&wait_for_change=true&last_etag="
	} else {
		suffix += "?wait_for_change=true&last_etag="
	}
	for {
		val, etag, err := c.getETag(suffix + url.QueryEscape(lastETag))
		if err != nil {
			if _, deleted := err.(NotDefinedError); !deleted {
				time.Sleep(failedSubscribeSleep)
				continue // Retry on other errors.
			}
			ok = false
		}
		lastETag = etag

		if err := fn(val, ok); err != nil || !ok {
			return err
		}
	}
}


type NotDefinedError string

func (suffix NotDefinedError) Error() string {
	return fmt.Sprintf("metadata: GCE metadata %q not defined", string(suffix))
}

// getETag returns a value from the metadata service as well as the associated ETag.
// This func is otherwise equivalent to Get.
func (c *MDS) getETag(suffix string) (value, etag string, err error) {
	ctx := context.TODO()
	// Using a fixed IP makes it very difficult to spoof the metadata service in
	// a container, which is an important use-case for local testing of cloud
	// deployments. To enable spoofing of the metadata service, the environment
	// variable GCE_METADATA_HOST is first inspected to decide where metadata
	// requests shall go.
	host := os.Getenv(metadataHostEnv)
	if host == "" {
		// Using 169.254.169.254 instead of "metadata" here because Go
		// binaries built with the "netgo" tag and without cgo won't
		// know the search suffix for "metadata" is
		// ".google.internal", and this IP address is documented as
		// being stable anyway.
		host = metadataIP
	}
	suffix = strings.TrimLeft(suffix, "/")
	u := "http://" + host + "/computeMetadata/v1/" + suffix
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	req.Header.Set("User-Agent", userAgent)
	var res *http.Response
	var reqErr error
	retryer := xnet.NewRetryer()
	for {
		res, reqErr = c.hc.Do(req)
		var code int
		if res != nil {
			code = res.StatusCode
		}
		if delay, shouldRetry := retryer.Retry(code, reqErr); shouldRetry {
			if err := xnet.Sleep(ctx, delay); err != nil {
				return "", "", err
			}
			continue
		}
		break
	}
	if reqErr != nil {
		return "", "", reqErr
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return "", "", NotDefinedError(suffix)
	}
	all, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", "", err
	}
	if res.StatusCode != 200 {
		return "", "", &Error{Code: res.StatusCode, Message: string(all)}
	}
	return string(all), res.Header.Get("Etag"), nil
}

// Error contains an error response from the server.
type Error struct {
	// Code is the HTTP response status code.
	Code int
	// Message is the server response message.
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("code=%d msg=`%s`", e.Code, e.Message)
}

// Get returns a value from the metadata service.
// The suffix is appended to "http://${GCE_METADATA_HOST}/computeMetadata/v1/".
//
// If the GCE_METADATA_HOST environment variable is not defined, a default of
// 169.254.169.254 will be used instead.
//
// If the requested metadata is not defined, the returned error will
// be of type NotDefinedError.
func (c *MDS) Get(suffix string) (string, error) {
	val, _, err := c.getETag(suffix)
	return val, err
}

const (
	// metadataIP is the documented metadata server IP address.
	metadataIP = "169.254.169.254"

	// metadataHostEnv is the environment variable specifying the
	// GCE metadata hostname.  If empty, the default value of
	// metadataIP ("169.254.169.254") is used instead.
	// This is variable name is not defined by any spec, as far as
	// I know; it was made up for the Go package.
	metadataHostEnv = "GCE_METADATA_HOST"

	//userAgent = "gcloud-golang/0.1"
	userAgent = "uk8s-golang/0.1"
)


