package meshauth

import (
	"context"
	"io/ioutil"
	"os"
	"sync"
	"time"
)

// Common token sources and interface.
//
// sts.go implements a OAuth2/SecureTokenService token source.
// mds.go implements a GCP-like HTTP token and metadata source.
// pkg/webpush/vapid implements a VAPID token source - but returns the full header, not just the token

// TokenSource is a common interface for anything returning Bearer or other kind of tokens.
type TokenSource interface {
	// GetToken for a given audience.
	GetToken(context.Context, string) (string, error)
}

type TokenSourceFunc func(context.Context, string) (string, error)

func (f TokenSourceFunc) GetToken(ctx context.Context, aud string) (string, error) {
	return f(ctx, aud)
}

// PerRPCCredentials defines the common interface for the credentials which need to
// attach security information to every RPC (e.g., oauth2).
// This is the interface used by gRPC - should be implemented by all TokenSource to
// allow use with gRPC.
type PerRPCCredentials interface {
	// GetRequestMetadata gets the current request metadata, refreshing
	// tokens if required. This should be called by the transport layer on
	// each request, and the data should be populated in headers or other
	// context. If a status code is returned, it will be used as the status
	// for the RPC. uri is the URI of the entry point for the request.
	// When supported by the underlying implementation, ctx can be used for
	// timeout and cancellation. Additionally, RequestInfo data will be
	// available via ctx to this call.
	// TODO(zhaoq): Define the set of the qualified keys instead of leaving
	// it as an arbitrary string.
	GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error)
	// RequireTransportSecurity indicates whether the credentials requires
	// transport security.
	RequireTransportSecurity() bool
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

// Old: LoadMeshEnv will Init the 'mesh-env' config map in istio-system, and save the
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

type MountedTokenSource struct {
	Base string
}

func (mds *MountedTokenSource) GetToken(ctx1 context.Context, aud string) (string, error) {
	b := mds.Base
	if b == "" {
		b = "/var/run/secrets/mesh/tokens/"
	}
	tokenFile := b + "/" + aud
	if _, err := os.Stat(tokenFile); err == nil {
		data, err := ioutil.ReadFile(tokenFile)
		if err != nil {
			return "", err
		} else {
			return string(data), nil
		}
	}
	return "", nil
}

// File or static token source
type FileTokenSource struct {
	TokenFile string
}

func (s *FileTokenSource) GetToken(context.Context, string) (string, error) {
	if s.TokenFile != "" {
		tfb, err := os.ReadFile(s.TokenFile)
		if err != nil {
			return "", err
		}
		return string(tfb), nil
	}
	return "", nil
}

type StaticTokenSource struct {
	Token string
}

func (s *StaticTokenSource) GetToken(context.Context, string) (string, error) {
	return s.Token, nil
}

type AudienceOverrideTokenSource struct {
	TokenSource TokenSource
	Audience    string
}

func (s *AudienceOverrideTokenSource) GetToken(ctx context.Context, _ string) (string, error) {
	return s.TokenSource.GetToken(ctx, s.Audience)
}


// ------------ Helpers around TokenSource

type PerRPCCredentialsFromTokenSource struct {
	TokenSource
}

func (s *PerRPCCredentialsFromTokenSource) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	t, err := s.GetToken(ctx, uri[0])
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"authorization": "Bearer " + t,
	}, nil
}

func (s *PerRPCCredentialsFromTokenSource) RequireTransportSecurity() bool { return false }


type TokenCache struct {
	cache sync.Map
	m     sync.Mutex

	TokenSource TokenSource

	// DefaultExpiration of tokens - 45 min if not set.
	// TokenSource doesn't deal with expiration, in almost all cases 1h retry is ok.
	DefaultExpiration time.Duration
}

func (c *TokenCache) Token(ctx context.Context, aud string) (string, error) {
	if got, f := c.cache.Load(aud); f {
		t := got.(*JWT)
		if t.Expiry().After(time.Now().Add(-time.Minute)) {
			return t.Raw, nil
		}
	}

	t, err := c.TokenSource.GetToken(ctx, aud)
	if err != nil {
		return "", err
	}

	_, j, _, _, err := JwtRawParse(t)

	if err != nil {
		te := c.DefaultExpiration
		if te == 0 {
			te = 45 * time.Minute
		}
		j = &JWT{Raw: t, Exp: time.Now().Add(te).Unix()}
	}

	c.cache.Store(aud, j)
	return t, nil
}
