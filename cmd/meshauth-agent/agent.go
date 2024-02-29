package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/costinm/meshauth"
	"github.com/costinm/meshauth/pkg/authz"
	k8sc "github.com/costinm/mk8s/k8s"
)

type Config struct {
	meshauth.MeshCfg `json:inline`

	// If set, init a local CA based on the configuration.
	CA *meshauth.CAConfig `json:"ca,omitempty"`

	// WIP: For each app instance, allocate a 'main' port as BasePort (equivalent to an 'environment') + AppPort.
	// Default base port is 15000 (Istio range), and
	// AppPort is reserved - 14 for the meshauth discovery agent.
	// Expect about 200 ports to be used - so BasePort is offset: 15000, 15200, 15400, ...
	// Additional ports for admin and mon are offset by 1000 - so on a VM we have an easy to configure set of ranges
	// for firewall and network policies.
	BasePort int
	AppPort  int

	AppName string

	MainMux  *http.ServeMux `json:-`
	AdminMux *http.ServeMux `json:-`
	MonMux   *http.ServeMux `json:-`

	MA *meshauth.MeshAuth `json:-`
}

// Listen will start listening for the agent.
func Listen(maCfg *Config, httpHandlerWrapper func(handler http.Handler, string2 string) http.Handler) {
	// Old Istio mixer port - used for check (authz)
	// https://istio.io/latest/docs/ops/deployment/requirements/
	// This is currently used by Istiod as prometheus monitoring port (for istiod only - agent is on 15020 and envoy 15090,
	// with 15021 for health)
	// This is a plain HTTP port

	if httpHandlerWrapper == nil {
		httpHandlerWrapper = func(handler http.Handler, string2 string) http.Handler {
			return handler
		}
	}

	go func() {
		err := http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", maCfg.BasePort+maCfg.AppPort), httpHandlerWrapper(maCfg.MainMux, maCfg.AppName))
		if err != nil {
			log.Fatal(err)
		}
	}()
	// Monitoring will use a separate range
	go func() {
		err := http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", maCfg.BasePort+maCfg.AppPort-1000), maCfg.MonMux)
		if err != nil {
			log.Fatal(err)
		}
	}()
	go func() {
		err := http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", maCfg.BasePort+maCfg.AppPort-2000), maCfg.AdminMux)
		if err != nil {
			log.Fatal(err)
		}
	}()
}

var stop = make(chan struct{})

func SetupAgent(ctx context.Context, maCfg *Config) (*meshauth.MeshAuth, error) {
	if maCfg.BasePort == 0 {
		maCfg.BasePort = 15000
	}
	if maCfg.AppPort == 0 {
		maCfg.AppPort = 14
	}
	if maCfg.AdminMux == nil {
		maCfg.AdminMux = http.DefaultServeMux
	}
	if maCfg.MonMux == nil {
		maCfg.MonMux = http.NewServeMux()
	}
	if maCfg.MainMux == nil {
		maCfg.MainMux = http.NewServeMux()
	}
	if maCfg.Namespace == "" {
		maCfg.Namespace = "default"
	}
	if maCfg.Name == "" {
		maCfg.Name = "default"
	}

	mux := maCfg.MainMux

	// Auto-detect the environment and SetupAgent mesh certificates, if any.
	// TODO: detect the istio-mounted istio-ca scoped token location and use it as a source.
	// On CloudRun or regular VMs - will not detect anything unless a secret is mounted.
	ma, err := meshauth.FromEnv(&maCfg.MeshCfg)
	if err != nil {
		return nil, err
	}

	// Init K8S - the agent is using a GKE kube config as bootstrap
	k := k8sc.NewK8S(&k8sc.K8SConfig{
		Namespace: ma.Namespace,
		KSA:       ma.Name,
	})
	err = k.InitK8SClient(ctx)
	if err != nil {
		return nil, err
	}

	if k.Default == nil {
		return nil, errors.New("Missing KUBECONFIG or in cluster")
	}

	p, _, _ := k.Default.GcpInfo()
	if maCfg.ProjectID == "" {
		maCfg.ProjectID = p
	}

	ma.AuthProviders["k8s"] = k.Default

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

	// TODO: handler to return the root cert, root SHA, public - and workload sha (DANE)

	authc := &authz.Authz{}

	//// start an echo server for testing and to reflect the requests
	//go http.ListenAndServe(":15099", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
	//	slog.Info("request", "headers", request.Header, "method", request.Method,
	//		"uri", request.URL)
	//	writer.WriteHeader(200)
	//	fmt.Fprintf(writer, "%s %v", request.Host, request.Header)
	//}))

	mux.HandleFunc("/echo/", func(writer http.ResponseWriter, request *http.Request) {
		host := request.Host
		fmt.Fprintf(writer, "host: %s, req: %s, headers: %v", host, request.RequestURI, request.Header)
		b := make([]byte, 1024)
		for {
			n, err := request.Body.Read(b)
			if err != nil {
				fmt.Fprintf(writer, "Err %v", err)
				return
			}
			log.Println(b[0:n])
			writer.Write(b[0:n])
		}
	})

	mux.HandleFunc("/wait/", func(writer http.ResponseWriter, request *http.Request) {
		host := request.Host
		fmt.Fprintf(writer, "host: %s, req: %s, headers: %v", host, request.RequestURI, request.Header)
		time.Sleep(60 * time.Second)
	})

	// Envoy proxy auth.
	//
	// TODO: check incoming JWTs, convert to headers
	// TODO: implement Istio authz policy
	// TODO: add prefix to envoy auth
	// TODO: add a JWT identifying the gateway (after determining the identity
	// using the IP and 'same node')
	mux.HandleFunc("/ext_authz/", authc.HandleExtAuthzAgent)

	// Required for golang detection of GCP MDS - there is no header except user-agent
	mux.HandleFunc("/", func(w http.ResponseWriter, request *http.Request) {
		w.Header().Add("Metadata-Flavor", "Google")
		w.WriteHeader(200)
		log.Println("DefaultCredentials check from", request.RemoteAddr)
	})

	return ma, nil
}
