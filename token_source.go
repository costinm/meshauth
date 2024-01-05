package meshauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Common token sources and interface.
// sts.go implements a OAuth2/SecureTokenService token source.

// K8STokenSource provides authentication and basic communication with a K8S cluster.
// The main purpose is to handle what is needed for auth and provisioning - loading
// secrets and config maps and getting tokens.
//
// K8S is an identity provider, and supports multiple credential types for exchange.
// If the app runs in K8S, it expects to find info in well-known locations.
// If it doesn't - it expects to have a KUBECONFIG or ~/.kube/config - or some
// other mechanism to get the address/credentials.
type K8STokenSource struct {
	// Dest is the common set of properties for any server we connect as client.
	// (hostname or IP, expected SANs and roots ).
	*Dest

	// Namespace and KSA - the 'cluster' credentials must have the RBAC permissions.
	// The user in the Cluster is typically admin - or may be the
	// same user, but have RBAC to call TokenRequest.
	Namespace      string
	ServiceAccount string
}

// TODO: Exec access, using /usr/lib/google-cloud-sdk/bin/gke-gcloud-auth-plugin (11M) for example
//  name: gke_costin-asm1_us-central1-c_td1
//  user:
//    exec:
//      apiVersion: client.authentication.k8s.io/v1beta1
//      command: gke-gcloud-auth-plugin
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

func (k *K8STokenSource) GetToken(ctx context.Context, aud string) (string, error) {
	return k.GetTokenRaw(ctx, k.Namespace, k.ServiceAccount, aud)
}

// GetTokenRaw returns a K8S JWT with specified namespace, name and audience. Caller must have the RBAC
// permission to act as the name.ns.
//
// Equivalent curl request:
//
//	token=$(echo '{"kind":"TokenRequest","apiVersion":"authentication.k8s.io/v1","spec":{"audiences":["istio-ca"], "expirationSeconds":2592000}}' | \
//	   kubectl create --raw /api/v1/namespaces/default/serviceaccounts/default/token -f - | jq -j '.status.token')
func (k *K8STokenSource) GetTokenRaw(ctx context.Context, ns, name, aud string) (string, error) {
	// If no audience is specified, something like
	//   https://container.googleapis.com/v1/projects/costin-asm1/locations/us-central1-c/clusters/big1
	// is generated ( on GKE ) - which seems to be the audience for K8S
	if ns == "" {
		ns = "default"
	}
	if name == "" {
		name = "default"
	}

	body := []byte(fmt.Sprintf(`{"kind":"TokenRequest","apiVersion":"authentication.k8s.io/v1","spec":{"audiences":["%s"]}}`, aud))

	rr := &RESTRequest{
		Method:    "POST",
		Namespace: ns,
		Kind:      "serviceaccount",
		Name:      name,
		Body:      body,
		Query:     "/token",
	}

	data, err := k.Do(rr.HttpRequest(ctx, k.Dest)) // k.RequestAll(ctx, "POST", ns, "serviceaccount", name+"/token", body, ""))

	if err != nil {
		return "", err
	}

	var secret CreateTokenResponse
	err = json.Unmarshal(data, &secret)
	if err != nil {
		return "", err
	}

	return secret.Status.Token, nil
}

func (k *K8STokenSource) Do(r *http.Request) ([]byte, error) {
	res, err := k.Dest.HttpClient().Do(r)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, errors.New(fmt.Sprintf("K8S error %d %s", res.StatusCode, string(data)))
	}
	return data, nil
}

//// Get a mesh env setting. May be replaced by an env variable.
//// Used to configure PROJECT_NUMBER and other internal settings.
//func (ms *K8STokenSource) GetEnv(k, def string) string {
//	v := os.Getenv(k)
//	if v != "" {
//		return v
//	}
//	v = ms.Env[k]
//	if v != "" {
//		return v
//	}
//
//	return def
//}
//

// Old: LoadMeshEnv will load the 'mesh-env' config map in istio-system, and save the
// settings. It had broad RBAC permissions. and included GCP settings.
//
// This is required for:
//   - getting the PROJECT_NUMBER, for GCP access/id token - used for stackdriver or MCP (not
//     required for federated tokens and certs)
//   - getting the 'mesh connector' address - used to connect to Istiod from 'outside'
//   - getting cluster info - if the K8S cluster is not initiated using a kubeconfig (we can
//     extract it from names).
//
// Replacement: control plane or user should set them, using automation on the initial config.
// or distribute along with system roots and bootstrap info, or use extended MDS.
//
// TODO: get cluster info by getting an initial token.
//func (def *K8STokenSource) LoadMeshEnv(ctx context.Context) error {
//	// Found a K8S cluster, try to locate configs in K8S by getting a config map containing Istio properties
//	cm, err := def.GetConfigMap(ctx, "istio-system", "mesh-env")
//	if def.Env == nil {
//		def.Env = map[string]string{}
//	}
//	if err == nil {
//		// Tokens using istio-ca audience for Istio
//		// If certificates exist, namespace/sa are initialized from the cert SAN
//		for k, v := range cm {
//			def.Env[k] = v
//		}
//	} else {
//		log.Println("Invalid mesh-env config map", err)
//		return err
//	}
//	if def.ProjectID == "" {
//		def.ProjectID = def.GetEnv("PROJECT_ID", "")
//	}
//	if def.Location == "" {
//		def.Location = def.GetEnv("CLUSTER_LOCATION", "")
//	}
//	if def.ClusterName == "" {
//		def.ClusterName = def.GetEnv("CLUSTER_NAME", "")
//	}
//	return nil
//}

// Equivalent config using shell:
//
//```shell
//CMD="gcloud container clusters describe ${CLUSTER} --zone=${ZONE} --project=${PROJECT}"
//
//K8SURL=$($CMD --format='value(endpoint)')
//K8SCA=$($CMD --format='value(masterAuth.clusterCaCertificate)' )
//```
//
//```yaml
//apiVersion: v1
//kind: Config
//current-context: my-cluster
//contexts: [{name: my-cluster, context: {cluster: cluster-1, user: user-1}}]
//users: [{name: user-1, user: {auth-provider: {name: gcp}}}]
//clusters:
//- name: cluster-1
//  cluster:
//    server: "https://${K8SURL}"
//    certificate-authority-data: "${K8SCA}"
//
//```
