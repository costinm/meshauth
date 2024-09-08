package ca

import (
	"context"
	"time"

	"github.com/costinm/meshauth"
	"github.com/costinm/meshauth/pkg/certs"
)

// Deprecated, to be replaced with certs package (no deps)

type CA struct {
	*certs.CA
}

// NewCA creates a new CA. Keys must be loaded.
func NewCA() *CA {
	ca := &CA{}
	ca.TrustDomain = "cluster.local"
	return ca
}

// NewTempCA creates a temporary/test CA.
func NewTempCA(trust string) *CA {
	if trust == "" {
		trust = "cluster.local"
	}
	cao := &CA{}
	cao.TrustDomain = trust
	cao.NewRoot()
	return cao
}

// NewIntermediaryCA creates a cert for an intermediary CA.
func (ca *CA) NewIntermediaryCA(trust, cluster string) *CA {
	return &CA{ca.CA.NewIntermediaryCA(trust, cluster)}
}

// New ID creates a new Mesh, with a certificate signed by this CA
//
// The cert will include both Spiffe identiy and DNS SANs.
func (ca *CA) NewID(ns, sa string, dns []string) *meshauth.Mesh {
	_, kp, cp := ca.NewTLSCert(ns, sa, dns)

	nodeID := meshauth.New(&meshauth.MeshCfg{})
	nodeID.AddRoots(ca.CACertPEM)
	// Will fill in trust domain, namespace, sa from the minted cert.
	nodeID.SetCertPEM(string(kp), string(cp))
	//nodeID.setTLSCertificate(crt)

	return nodeID
}

func (a *CA) GetToken(ctx context.Context, sub, aud, iss string) (string, error) {
	jwt := &meshauth.JWT{
		Aud: []string{aud},
		Exp: time.Now().Add(1 * time.Hour).Unix(),
		Sub: sub,
		Iss: iss,
	}
	return jwt.Sign(a.Private), nil
}



