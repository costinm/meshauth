package mdb

import (
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/costinm/meshauth"
)

// mdb holds a mesh database - can be a full or partial view of the IPs and hostnames that
// part of the mesh. Mesh is defined as set of workloads that have verifiable identity and
// may communicate securely using L4 secure network (ambient, secure CNI) or mTLS or workload JWT+TLS.

type MDB struct {
	IPToW sync.Map

	NameToW sync.Map

	Services sync.Map
}

func (mdb *MDB) ByIP(addr string) *meshauth.Dest {
	return nil
}

func (mdb *MDB) ByName(addr string) *meshauth.Dest {
	return nil
}

func (mdb *MDB) HandleK8S(writer http.ResponseWriter, request *http.Request) {
	parts := strings.Split(request.RequestURI, "/")
	ns := parts[5]
	slog.Info("k8s request", "headers", request.Header, "method", request.Method,
		"uri", request.URL, "parts", parts, "ns", ns)

	writer.WriteHeader(404)
}
