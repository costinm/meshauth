package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"log/slog"

	"github.com/costinm/meshauth"
	"github.com/costinm/meshauth/pkg/mdb"
	gke "github.com/costinm/mk8s/gcp"
	k8sip "github.com/costinm/mk8s/ip"
	sshd "github.com/costinm/ssh-mesh"
	"github.com/costinm/utel"
	"github.com/costinm/utel/otelbootstrap"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	//gcp "github.com/costinm/meshauth/gcloud"
	"github.com/costinm/meshauth/util"
	k8sc "github.com/costinm/mk8s/k8s"
)

const appName = "xmdsd"

func init() {
	// Init telemetry and logging with default/env settings. Once config is loaded dynamic config may be used.
	// This installs a json logger with a custom handler.
	// Done in init so any call to log from init or var initialization will use this logger.
	// utel.Handlers has a map of Handlers - with "default" set to the slog default handler.
	// Each handler also registers an expvar logger.NAME metric counting activity.
	utel.InitSlogDefaults()
}

// TODO: use a dynamic flag library - like "fortio.org/dflag"

// Central (remote) xMDS server.
// Similar functionality to the agent, but using HTTPS or network security (ambient, native)
// and running in K8S, CloudRun or on any remote VM instead of per node.
// Like the agent it can return metadata and mesh tokens - the agent is restricted to same-node
func main() {
	ctx := context.Background()

	// param ends up as Resource[service.name]
	ot := otelbootstrap.NewOTel(appName)
	defer ot.OnStop(ctx)

	ot.InitOTelHost()
	ot.InitTracing(ctx)
	ot.InitMetrics(nil)

	// name ends up as "InstrumentataionLibrary.start
	traceStart := otel.Tracer("xmds-start")
	ctx, spanStart := traceStart.Start(ctx, "sync")

	maCfg := &Config{}
	t0 := time.Now()

	// Lookup config file, init basic main file.
	util.MainStart(appName, maCfg)

	meterSync := otel.Meter("k8s.sync")
	varzK8SStartup, _ := meterSync.Int64Counter("startup")

	k := k8sc.NewK8S(&k8sc.K8SConfig{
		Namespace: maCfg.Namespace,
		KSA:       maCfg.Name,
	})
	err := k.InitK8SClient(ctx)

	// Explicit setting to enable a GCP SA.
	projectid := os.Getenv("PROJECT_ID")
	if projectid != "" && maCfg.AuthnConfig.CloudrunIAM {
		// TODO: get it from MDS

		// bootstrap with GCP credentials. Source of trust is a google account from file or MDS.
		// The CA should run in cloudrun or a trusted VM or separate node pool/cluster.
		// The SA of the CA can be granted impersonation/token to other GSA and KSA.
		// It can check node-pod relation.
		//err := gke.GcpInit(ctx, ma, "k8s-istio-system@"+projectid+".iam.gserviceaccount.com")
		//if err != nil {
		//}
		gkec := gke.NewGKE()
		err = gkec.InitGKE(ctx)
		if err != nil {
			log.Panic(err)
		}

		if gkec.Cluster != nil {
			rc := gkec.Cluster.RestConfig()
			k.Default = &k8sc.K8SCluster{
				Name:      "incluster",
				Namespace: os.Getenv("POD_NAMESPACE"),
			}

			err = k.Default.InitConfig(rc)
			if err != nil {
				log.Panic(err)
			}
		}

	}

	if k.Default == nil {

	}

	maCfg.K8S = k
	// Look for kube config - merge it into the cluster set.
	// k.LoadKubeConfig("")

	// TODO: Add any GKE accessible clusters.

	maCfg.MainMux = http.NewServeMux()
	SetupCA(ctx, maCfg, k)

	// Agent defaults to 150 + 14... -
	// Server defaults to 152xx
	if maCfg.BasePort == 0 {
		maCfg.BasePort = 15200
	}
	ma, err := SetupAgent(ctx, maCfg)
	if err != nil {
		log.Fatal(err)
	}

	// Set the IP watcher
	mdbs := &mdb.MDB{}
	kd := &k8sip.K8SData{MDB: mdbs}
	pods, err := k8sip.Start(kd, k.Default.Config)
	if err != nil {
		log.Fatal(err)
	}
	pods.WaitForInit(ma.Stop)

	// Experimental K8S-style API
	maCfg.MainMux.HandleFunc("/apis/meshauth.io/v1/namespaces/", mdbs.HandleK8S)
	// Experimental Github-like SSH keys info. Username and /keys processed by handler
	// Gitea uses /api/v1/ prefix but requires authz.
	// Result is array, with "key" in each obj as an authorized key.
	maCfg.MainMux.HandleFunc("/users/", mdbs.HandleK8S)

	varzK8SStartup.Add(ctx, int64(time.Since(t0)))

	auth := meshauth.NewAuthn(maCfg.AuthnConfig)
	//auth.Verify = oidc.Verify

	// Setup the wrapper
	Listen(maCfg, func(handler http.Handler, string2 string) http.Handler {
		return ot.HttpHandler(&meshauth.AuthHandlerWrapper{
			Handler: handler,
			Logger:  slog.Default(),
			Auth:    auth}, string2)
	})

	// Also listen on http2 (agent doesn't need this)
	// Used for gRPC and http - in connect go they can be safely shared.
	h2addr := fmt.Sprintf(":%d", maCfg.BasePort+32)
	h2Lis, err := net.Listen("tcp", h2addr)
	if err != nil {
		log.Fatal(err)
	}
	h2server := &http.Server{
		Addr:    h2addr,
		Handler: h2c.NewHandler(maCfg.MainMux, &http2.Server{}),
	}
	go h2server.Serve(h2Lis)

	jsonCfg, _ := json.Marshal(maCfg)

	// TODO: replace with slog.
	spanStart.AddEvent("cfg", trace.WithAttributes(attribute.String("cfg", string(jsonCfg))))

	spanStart.End()

	util.MainEnd()
}

// Run a lighter, HTTP-based cert generation for Spiffee and SSH certs.
// Backed by a key in filesystem (mounted secret in Cloudrun or docker) or in the
// primary K8S cluster.
//
// If no key found - continue without cert signing.
// TODO: add an option to fail if no cert found
func SetupCA(ctx context.Context, cfg *Config, k *k8sc.K8S) {
	mux := cfg.MainMux

	if cfg.CA == nil || cfg.CA.RootLocation == "" {
		return
	}

	// Explicit setting if CA is mounted
	caDir := os.Getenv("CA_DIR")
	if caDir == "" {
		caDir = "."
	}
	// Attempt to load roots from filesystem
	ca := meshauth.NewCA(cfg.CA)
	// CAFromEnv(caDir)

	// If not found:
	if ca.Private == nil && k.Default != nil {
		s, err := k.GetSecret(ctx, "istio-system", "istio-ca-secret")
		if err == nil {
			// CertManager style - ca.crt may also be present.
			k := s["tls.key"]
			crt := s["tls.crt"]
			err = ca.SetCert(k, crt)
			if err != nil {
				slog.Info(":CA.Init", "err", err)
			}
		} else {
			slog.Info(":CA.Init.K8SSecret", "err", err)
		}

		// TODO: save it
	}

	//
	if ca.Private != nil {
		slog.InfoContext(ctx, "CA-START", "ca_subject", ca.CACert.Subject)

		s, err := ssh.NewSignerFromKey(ca.Private)
		if err != nil {
			sshCA, _ := sshd.NewSSHMesh(&sshd.SSHConfig{})
			// Will be used to sign certificates
			sshCA.SignerHost = s

			ca.ExtraKeyProvider = func(public interface{}, id string, secret *meshauth.Secret) {
				sshpk, err := ssh.NewPublicKey(public)
				if err != nil {
					slog.Info("Invalid public", "err", err)
					return
				}
				h, _, err := sshCA.Sign(sshpk, ssh.HostCert, []string{id})
				secret.Data["ssh-host"] = h
			}
		}

		// Create an identity for the CA as istiod.
		ma := ca.NewID("istio-system", "istiod", nil)
		cfg.MA = ma

		mux.HandleFunc("/apis/certs.mesh.io/v1/namespaces/", ca.NewCertificate)
		// Public
		mux.HandleFunc("/.well-known/openid-configuration", ma.HandleDisc)
		mux.HandleFunc("/.well-known/jwks", ca.HandleJWK)
	}

	// - use standard ssh config files - can be mounted from a Secret or local files
	// - 'admin' can create certificates, using ssh command
	// - all authorized users can forward
	//sshCA.Init(caDir)

	// TODO: roots
	//

}
