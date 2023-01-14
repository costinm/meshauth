package meshauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/costinm/meshauth/k8s"
)

type K8SCluster struct {
	Addr  string
	ID    string
	Token string

	CACertPEM []byte

	Namespace      string
	ServiceAccount string
	Env            map[string]string
	AuthProviders  map[string]interface{}

	HttpClient HttpClient
	Location   string
	ProjectID  string
	Path       string
	// TokenProvider is used to get 'admin' tokens (with RBAC permission to get other kinds
	// of tokens and configs)
	TokenProvider func(ctx context.Context, aud string) (string, error)
	Server        string
	TokenFile     string
}

// K8STokenSource returns K8S JWTs via "/token" requests.
// TODO: or file-mounted secrets
type K8STokenSource struct {

	// Namespace and KSA - the 'cluster' credentials must have the RBAC permissions.
	Namespace, KSA string

	// Force this audience instead of derived from request URI.
	AudOverride string
	k           *K8SCluster
}

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// To keep things simple and dependency-free, this is a copy of few structs
// used in K8S and Istio.
//
// K8S stores the .json format in CRDS - which is what this package uses directly.
//
// Changes:
// - only a subset, few unused fields commented out
// - enums converted to 'string', to make json conversion easy.

func (k *K8SCluster) Request(ctx context.Context, baseURL string, ns, kind, name string, postdata []byte) *http.Request {
	path := fmt.Sprintf("/api/v1/namespaces/%s/%ss/%s",
		ns, kind, name)
	var req *http.Request
	if postdata == nil {
		req, _ = http.NewRequestWithContext(ctx, "GET", baseURL+path, nil)
	} else {
		req, _ = http.NewRequestWithContext(ctx, "POST", baseURL+path, bytes.NewReader(postdata))
	}
	req.Header.Add("content-type", "application/json")
	if k.Token != "" {
		req.Header.Add("authorization", "Bearer "+k.Token)
	}
	if k.TokenFile != "" {
		// TODO: cache the token, check expiration
		td, err := ioutil.ReadFile(k.TokenFile)
		if err == nil {
			req.Header.Add("authorization", "Bearer "+string(td))
		}
	}

	return req
}

// Wrapper around ConfigMap - returns the data content.
// Returns an error if map can't be parsed or request fails.
func (k *K8SCluster) GetConfigMap(ctx context.Context, ns string, name string) (map[string]string, error) {
	res, err := k.HttpClient.Do(k.Request(ctx, k.Server, ns, "configmap", name, nil))
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(res.Body)
	var secret k8s.ConfigMap
	err = json.Unmarshal(data, &secret)
	if err != nil {
		return nil, err
	}

	return secret.Data, nil
}

func NewK8STokenSource(k *K8SCluster) *K8STokenSource {
	return &K8STokenSource{
		k: k,
	}
}

func (f *K8STokenSource) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	t, err := f.GetToken(ctx, uri[0])
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"authorization": "Bearer " + t,
	}, nil
}

func (f *K8SCluster) RequireTransportSecurity() bool {
	return true
}

func (f *K8SCluster) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	t, err := f.GetToken(ctx, uri[0])
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"authorization": "Bearer " + t,
	}, nil
}

func (f *K8STokenSource) RequireTransportSecurity() bool {
	return true
}

func (ts *K8STokenSource) GetToken(ctx context.Context, aud string) (string, error) {
	if ts.AudOverride != "" {
		aud = ts.AudOverride
	}

	// TODO: file based access, using /var/run/secrets/ file pattern and mounts.
	// TODO: Exec access, using /usr/lib/google-cloud-sdk/bin/gke-gcloud-auth-plugin (11M) for example
	//  name: gke_costin-asm1_us-central1-c_td1
	//  user:
	//    exec:
	//      apiVersion: client.authentication.k8s.io/v1beta1
	//      command: gke-gcloud-auth-plugin
	//      installHint: Install gke-gcloud-auth-plugin for use with kubectl by following
	//        https://cloud.google.com/blog/products/containers-kubernetes/kubectl-auth-changes-in-gke
	//      provideClusterInfo: true

	// /usr/lib/google-cloud-sdk/bin/gke-gcloud-auth-plugin
	// {
	//    "kind": "ExecCredential",
	//    "apiVersion": "client.authentication.k8s.io/v1beta1",
	//    "spec": {
	//        "interactive": false
	//    },
	//    "status": {
	//        "expirationTimestamp": "2022-07-01T15:55:01Z",
	//        "token": ".." // ya29
	//    }
	//}
	return ts.k.GetTokenRaw(ctx, ts.Namespace, ts.KSA, aud)

}

func (k *K8SCluster) GetToken(ctx context.Context, aud string) (string, error) {
	return k.GetTokenRaw(ctx, aud, k.Namespace, k.ServiceAccount)
}

// GetTokenRaw returns a K8S JWT with specified namespace, name and audience. Caller must have the RBAC
// permission to act as the name.ns.
//
// Equivalent curl request:
//
//	token=$(echo '{"kind":"TokenRequest","apiVersion":"authentication.k8s.io/v1","spec":{"audiences":["istio-ca"], "expirationSeconds":2592000}}' | \
//	   kubectl create --raw /api/v1/namespaces/default/serviceaccounts/default/token -f - | jq -j '.status.token')
func (k *K8SCluster) GetTokenRaw(ctx context.Context, ns, name, aud string) (string, error) {
	// If no audience is specified, something like
	//   https://container.googleapis.com/v1/projects/costin-asm1/locations/us-central1-c/clusters/big1
	// is generated ( on GKE ) - which seems to be the audience for K8S
	if ns == "" {
		ns = "default"
	}
	if name == "" {
		name = "default"
	}

	body := []byte(fmt.Sprintf(`
{"kind":"TokenRequest","apiVersion":"authentication.k8s.io/v1","spec":{"audiences":["%s"]}}
`, aud))
	data, err := k.Do(k.Request(ctx, k.Server, ns, "serviceaccount", name+"/token", body))

	if err != nil {
		return "", err
	}

	var secret k8s.CreateTokenResponse
	err = json.Unmarshal(data, &secret)
	if err != nil {
		return "", err
	}

	return secret.Status.Token, nil
}

func (k *K8SCluster) Do(r *http.Request) ([]byte, error) {
	res, err := k.HttpClient.Do(r)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, errors.New(fmt.Sprintf("Error getting token %d %s", res.StatusCode, string(data)))
	}
	return data, nil

}

// Get a mesh env setting. May be replaced by an env variable.
// Used to configure PROJECT_NUMBER and other internal settings.
func (ms *K8SCluster) GetEnv(k, def string) string {
	v := os.Getenv(k)
	if v != "" {
		return v
	}
	v = ms.Env[k]
	if v != "" {
		return v
	}

	return def
}

// InitK8S will detect k8s env, and if present will load the mesh defaults and init
// authenticators.
func InitK8S(ctx context.Context, kc *k8s.KubeConfig) (*K8SCluster, map[string]*K8SCluster, error) {
	var err error
	var def *K8SCluster
	var extra map[string]*K8SCluster
	if kc != nil {
		def, extra, err = addKubeConfigClusters(kc)
		if err != nil {
			return nil, nil, err
		}
	}

	if def == nil {
		def, err = inCluster()
	}
	if err != nil {
		return nil, nil, err
	}

	if def == nil {
		// Not in K8S env
		return nil, nil, nil
	}
	return def, extra, nil
}

func (def *K8SCluster) LoadMeshEnv(ctx context.Context) error {
	// Found a K8S cluster, try to locate configs in K8S by getting a config map containing Istio properties
	cm, err := def.GetConfigMap(ctx, "istio-system", "mesh-env")
	if def.Env == nil {
		def.Env = map[string]string{}
	}
	if err == nil {
		// Tokens using istio-ca audience for Istio
		// If certificates exist, namespace/sa are initialized from the cert SAN
		for k, v := range cm {
			def.Env[k] = v
		}
	} else {
		log.Println("Invalid mesh-env config map", err)
		return err
	}
	return nil
}

func (k *K8SCluster) NewK8STokenSource(audOverride string) *K8STokenSource {
	return &K8STokenSource{
		k:           k,
		AudOverride: audOverride,
		Namespace:   k.Namespace, KSA: k.ServiceAccount,
	}
}

func (def *K8SCluster) GCPFederatedSource(ctx context.Context) (*STS, error) {
	// Init a GCP token source - using K8S provider and exchange.
	// TODO: if we already have a GCP GSA, we can use that directly.
	projectNumber := def.GetEnv("PROJECT_NUMBER", "")
	projectId := def.GetEnv("PROJECT_ID", "")
	clusterLocation := def.GetEnv("CLUSTER_LOCATION", "")
	clusterName := def.GetEnv("CLUSTER_NAME", "")

	if projectId != "" && clusterName != "" && clusterLocation != "" && projectNumber != "" {
		sts := NewFederatedTokenSource(&AuthConfig{
			TrustDomain: projectId + ".svc.id.goog",
			ClusterAddress: fmt.Sprintf("https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s",
				projectId, clusterLocation, clusterName),

			// Will use TokenRequest to get tokens with AudOverride
			TokenSource: &K8STokenSource{
				k:           def,
				AudOverride: projectId + ".svc.id.goog",
				Namespace:   def.Namespace,
				KSA:         def.ServiceAccount},
		})
		return sts, nil
	}
	return nil, nil
}

func (def *K8SCluster) GCPAccessTokenSource(ctx context.Context) (*STS, error) {
	// Init a GCP token source - using K8S provider and exchange.
	// TODO: if we already have a GCP GSA, we can use that directly.
	projectNumber := def.GetEnv("PROJECT_NUMBER", "")
	projectId := def.GetEnv("PROJECT_ID", "")
	clusterLocation := def.GetEnv("CLUSTER_LOCATION", "")
	clusterName := def.GetEnv("CLUSTER_NAME", "")

	if projectId != "" && clusterName != "" && clusterLocation != "" && projectNumber != "" {
		// This returns JWT tokens for k8s
		//audTokenS := k8s.K8STokenSource{Cluster: k8sdefault, Namespace: hb.Namespace,
		//	KSA: hb.ServiceAccount}
		audTokenS := NewGSATokenSource(&AuthConfig{
			ProjectNumber: projectNumber,
			TrustDomain:   projectId + ".svc.id.goog",
			ClusterAddress: fmt.Sprintf("https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s",
				projectId, clusterLocation, clusterName),
			TokenSource: &K8STokenSource{
				k:         def,
				Namespace: def.Namespace,
				KSA:       def.ServiceAccount},
		}, "")
		return audTokenS, nil
	}
	return nil, nil
}

// AddKubeConfigClusters extracts supported RestClusters from the kube config, returns the default and the list
// of clusters by location.
// GKE naming conventions are assumed for extracting the location.
//
// URest is used to configure TokenProvider and as factory for the http client.
// Returns the default client and the list of non-default clients.
func addKubeConfigClusters(kc *k8s.KubeConfig) (*K8SCluster, map[string]*K8SCluster, error) {
	var cluster *k8s.KubeCluster
	var user *k8s.KubeUser

	if kc == nil {
		return nil, nil, nil
	}

	cByName := map[string]*K8SCluster{}

	if len(kc.Contexts) == 0 || kc.CurrentContext == "" {
		if len(kc.Clusters) == 0 || len(kc.Users) == 0 {
			return nil, cByName, nil
		}
		user = &kc.Users[0].User
		cluster = &kc.Clusters[0].Cluster
		rc, err := kubeconfig2Rest("default", cluster, user, "default")

		if err != nil {
			return nil, nil, err
		}
		return rc, nil, nil
	}

	// Have contexts
	for _, cc := range kc.Contexts {
		for _, c := range kc.Clusters {
			c := c
			if c.Name == cc.Context.Cluster {
				cluster = &c.Cluster
			}
		}
		for _, c := range kc.Users {
			c := c
			if c.Name == cc.Context.User {
				user = &c.User
			}
		}
		cc := cc
		rc, err := kubeconfig2Rest(cc.Context.Cluster, cluster, user, cc.Context.Namespace)
		if err != nil {
			log.Println("Skipping incompatible cluster ", cc.Context.Cluster, err)
		} else {
			cByName[cc.Name] = rc
		}
	}

	if len(cByName) == 0 {
		return nil, nil, errors.New("no clusters found")
	}
	defc := cByName[kc.CurrentContext]
	if defc == nil {
		for _, c := range cByName {
			defc = c
			break
		}
	}
	return defc, cByName, nil
}

func kubeconfig2Rest(name string, cluster *k8s.KubeCluster, user *k8s.KubeUser, ns string) (*K8SCluster, error) {
	if ns == "" {
		ns = "default"
	}
	u, err := url.Parse(cluster.Server)
	h := u.Hostname()
	p := u.Port()
	if err != nil {
		return nil, err
	}
	if p == "" {
		p = "443"
	}
	prefix := "http://"
	if p == "443" || cluster.CertificateAuthority != "" || cluster.CertificateAuthorityData != "" {
		prefix = "https://"
	}
	rc := &K8SCluster{
		Server: cluster.Server,
		Addr:   prefix + net.JoinHostPort(h, p),
		Path:   u.Path,
	}
	if user.Token != "" {
		rc.Token = user.Token
	}
	if user.TokenFile != "" {
		rc.TokenFile = user.TokenFile
	}

	parts := strings.Split(name, "_")
	if parts[0] == "gke" {
		//rc.ProjectId = parts[1]
		rc.Location = parts[2]
		rc.ProjectID = parts[1]
		rc.ID = parts[3]
	} else {
		rc.ID = name
	}

	// May be useful to AddService: strings.HasPrefix(name, "gke_") ||
	//if user.AuthProvider.Name != "" {
	//	rc.TokenProvider = uk.AuthProviders[user.AuthProvider.Name]
	//	if rc.TokenProvider == nil {
	//		return nil, errors.New("Missing provider " + user.AuthProvider.Name)
	//	}
	//}

	// TODO: support client cert, token file (with reload)
	if cluster.CertificateAuthority != "" {
		caCert, err := ioutil.ReadFile(cluster.CertificateAuthority)
		if err != nil {
			return nil, err
		}
		rc.CACertPEM = caCert
	}
	caCert, err := base64.StdEncoding.DecodeString(string(cluster.CertificateAuthorityData))
	if err != nil {
		return nil, err
	}
	rc.CACertPEM = caCert

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cluster.InsecureSkipTLSVerify,
	}

	if len(rc.CACertPEM) != 0 {
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(rc.CACertPEM) {
			return nil, errors.New("certificate authority doesn't contain any certificates")
		}
	}

	rc.HttpClient = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return rc, nil
}

func inCluster() (*K8SCluster, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	if host != "" {
		const (
			tokenFile  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
			rootCAFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
		)
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if len(host) == 0 || len(port) == 0 {
			return nil, nil
		}

		token, err := ioutil.ReadFile(tokenFile)
		if err != nil {
			return nil, err
		}

		ca, err := ioutil.ReadFile(rootCAFile)
		c := &K8SCluster{
			Addr:      net.JoinHostPort(host, port),
			Server:    "https://" + net.JoinHostPort(host, port),
			ID:        "k8s",
			TokenFile: tokenFile,
			CACertPEM: ca,
		}

		namespace, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err == nil {
			c.Namespace = string(namespace)
		}

		jwt := DecodeJWT(string(token))
		if c.Namespace == "" {
			c.Namespace = jwt.K8S.Namespace
		}
		if c.ServiceAccount == "" {
			c.ServiceAccount = jwt.Name
		}

		return c, nil
	}
	return nil, nil
}
