package main

import (
	"context"
	"log"
	"log/slog"

	"github.com/costinm/meshauth/cmd"
	"github.com/costinm/meshauth/util"
	"github.com/costinm/utel"
	uotel "github.com/costinm/utel/otel"
	"go.opentelemetry.io/otel"
)

// Meshauth-agent  can run on a local dev machine, in a docker container or in K8S deamonet set
// or sidecar. Will emulate an MDS server to provide tokens and meta.
//
// TODO: It also handles ext_authz http protocol from Envoy.
// TODO: maintain k8s-like JWT and cert to emulate in-cluster
//
// Source of auth:
// - kube config with token (minimal deps) or in-cluster - for running in K8S
//
// - TODO: MDS in a VM/serverless - with permissions to the cluster
//
//	Non-configurable port 15014 - iptables should redirect port 80 of the MDS.
//
// iptables -t nat -A OUTPUT -p tcp -m tcp -d 169.254.169.254 --dport 80 -j REDIRECT --to-ports 15014
//
// For envoy and c++ grpc - requires /etc/hosts or resolver for metadata.google.internal.
//
// Alternative: use ssh-mesh or equivalent to forward to real MDS.
//
func main() {

	ctx := context.Background()

	slog.SetDefault(slog.New(utel.InitDefaultHandler(nil)))
	uotel.InitTracing()
	uotel.InitExpvarMetrics()

	maCfg := &cmd.Config{}

	// name ends up as "InstrumentataionLibrary.start
	traceStart := otel.Tracer("xmds-start")

	ctx, spanStart := traceStart.Start(ctx, "sync")

	// Lookup config file, init basic main file.
	util.MainStart("mds", maCfg)

	_, err := cmd.SetupAgent(ctx, maCfg)
	if err != nil {
		log.Fatal(err)
	}

	spanStart.End()

	cmd.Listen(maCfg, nil)

	util.MainEnd()
}
