package test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/costinm/meshauth"
	"github.com/costinm/meshauth/pkg/apis/authn"
	"github.com/costinm/meshauth/pkg/ca"
	"github.com/costinm/meshauth/pkg/mdsd"
	"github.com/costinm/meshauth/pkg/stsd"
	"github.com/costinm/meshauth/pkg/tokens"
)

func TestJWKS(t *testing.T) {
	ctx := context.Background()

	// Init the CA - this normally runs on a remote server with ACME certs.
	ca := ca.NewCA()
	err := ca.Init("../../testdata/ca")
	if err != nil {
		t.Fatal(err)
	}

	mauth := ca.NewID("istio-system", "istiod", nil)

	laddr := startServer(t, ca, mauth)
	// TODO: start an auth server

	cfg := &authn.AuthnConfig{
		Issuers: []*authn.TrustConfig{
			&authn.TrustConfig{
				Issuer: "https://accounts.google.com",
			},
			&authn.TrustConfig{
				Issuer: "https://container.googleapis.com/v1/projects/costin-asm1/locations/us-central1-c/clusters/big1",
			},
			//&TrustConfig{
			//	Issuer: laddr,
			//},
		},
	}
	ja := tokens.NewAuthn(cfg)

	l := &authn.TrustConfig{
		Issuer: "http://" + laddr,
	}
	err = ja.UpdateKeys(ctx, l)
	if err != nil {
		t.Error(err)
	}

	err = ja.FetchAllKeys(ctx, cfg.Issuers)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(cfg.Issuers[0].Jwks)

	// Client tests
	ctx, cf := context.WithTimeout(context.Background(), 500*time.Second)
	defer cf()

	// Will get K8S tokens to authenticate, with istio-ca audience
	stsc := stsd.NewFederatedTokenSource(&stsd.STSAuthConfig{
		STSEndpoint: "http://" + laddr + "/v1/token",
		TokenSource: &CATokenSource{CA: ca, Sub: "test", Iss: "http://ca"}, // def.NewK8STokenSource("istio-ca"),
		AudienceSource: "istio-ca",
	})

	_, err = stsc.GetToken(ctx, "http://foo.com")
	if err != nil {
		t.Fatal("STSc token ", err)
	}

	mdsc := &mdsd.MDS{
		Addr: "http://" + laddr + "/computeMetadata/v1",
	}

	_, err = mdsc.GetToken(ctx, "http://foo.com")
	if err != nil {
		t.Fatal("getting token from MDS", err)
	}

	// Use the private CA server to get a token and initialize a client
	istio_ca, err := mdsd.Get(mauth).GetToken(ctx, "istio-ca")
	if err != nil {
		t.Fatal(err)
	}
	checkJWT(t, istio_ca)

}

type CATokenSource struct {
	Sub string
	CA  *ca.CA
	Iss string
}

func (C CATokenSource) GetToken(ctx context.Context, aud string) (string, error) {
	return C.CA.GetToken(ctx, C.Sub, aud, C.Iss)
}

// startServer will start a basic XMDS server, with deps-free packages.
// - ca and JWT signing - using testdata
// - local metadata server
//
// TODO: alternative is to run xmdsd in testdata dir.
func startServer(t *testing.T, ca *ca.CA, mauth *meshauth.Mesh) string {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 0})
	if err != nil {
		t.Fatal("Listen")
	}
	_, p, _ := net.SplitHostPort(l.Addr().String())
	addr := fmt.Sprintf("localhost:%s", p)

	authn := tokens.NewAuthn(&authn.AuthnConfig{
		Issuers: []*authn.TrustConfig{
			&authn.TrustConfig{
				Issuer: "http://" + addr,
			},
			&authn.TrustConfig{
				Issuer: "http://ca",
				Jwks: ca.GetJWK(),
			},
		},
	})
	// An STS server returning tokens signed by the CA.
	sts := &stsd.TokenExchangeD{
		Authn: authn,
		Generate: func(ctx context.Context, jwt *meshauth.JWT, aud string) (string, error) {
			return ca.GetToken(ctx, "test", aud, "")
		},
	}

	mux := &http.ServeMux{}

	mux.Handle("/v1/token", sts)

	mdsd.SetupAgent(mauth, mux)
	mux.HandleFunc("/.well-known/openid-configuration", mauth.HandleDisc)
	mux.HandleFunc("/.well-known/jwks", ca.HandleJWK)
	mux.HandleFunc("/jwks", ca.HandleJWK)

	// An MDS server should be able to proxy OIDC and know/cache JWK.

	// TODO: init a per-node intermediate CA that can sign tokens for the node or cluster.

	go http.Serve(l, mux)

	return addr
}

func checkJWT(t *testing.T, jwt string) {

	r, _ := http.NewRequest("GET", "http://example", nil)
	// Expired key - issue a new one
	r.Header["Authorization"] = []string{"bearer " + jwt}

	// Example of google JWT in cloudrun:
	// eyJhbGciOiJSUzI1NiIsImtpZCI6IjBlNzJkYTFkZjUwMWNhNmY3NTZiZjEwM2ZkN2M3MjAyOTQ3NzI1MDYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIzMjU1NTk0MDU1OS5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1ZCI6IjMyNTU1OTQwNTU5LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTA0MzY2MjYxNjgxNjMwMTM4NTIzIiwiZW1haWwiOiJjb3N0aW5AZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJ1MTIwMzhrTTh2THcyZGN0dnVvbTdBIiwiaWF0IjoxNzAwODg0MDAwLCJleHAiOjE3MDA4ODc2MDB9.SIGNATURE_REMOVED_BY_GOOGLE"

	cfg := &authn.AuthnConfig{}

	cfg.Issuers = []*authn.TrustConfig{{Issuer: "https://accounts.google.com"}}

	ja := tokens.NewAuthn(cfg)

	// May use a custom method too with lower deps
	//ja.Verify = oidc.Verify

	err := ja.Auth(nil, r)
	if err != nil {
		t.Fatal(err)
	}
}
func TestXFCC(t *testing.T) {
	vals := tokens.ParseXFCC(`By=spiffe://cluster.local/ns/ssh-ca/sa/default;Hash=8813da93b;Subject="";URI=spiffe://cluster.local/ns/sshd/sa/default`)
	if vals["By"] != "spiffe://cluster.local/ns/ssh-ca/sa/default" {
		t.Error("Missing By")
	}

	if vals["URI"] != "spiffe://cluster.local/ns/sshd/sa/default" {
		t.Error("Missing URI")
	}

}
