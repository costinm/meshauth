package ugcp

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"testing"

	"github.com/costinm/meshauth/pkg/certs"
	"github.com/costinm/meshauth/pkg/tokens"
)

func TestGCP2(t *testing.T) {
	ctx := context.Background()
	g := GCPAuth{}
	g.Provision(ctx)

	oa := g.TokenProvider

	log.Println(oa)

	tok, err := oa.GetToken(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	log.Println(tok[0:10])

	jtok, err := oa.GetToken(ctx, "32555940559.apps.googleusercontent.com")
	if err != nil {
		t.Fatal(err)
	}
	jjtok := tokens.DecodeJWT(jtok)
	log.Println(jjtok)
	jtok1, err := oa.GetToken(ctx, "584624515903.apps.googleusercontent.com")
	if err != nil {
		t.Error(err)
	} else {
		t.Log(jtok1)
	}

	g.ProjectID = "dmeshgate" // -406315"
	//g.Debug = true

	t.Run("gke", func(t *testing.T) {
		cd, err := g.GKEClusters(ctx)
		if err != nil {
			t.Fatal(err)
		}
		log.Println(cd)
	})

	t.Run("hub", func(t *testing.T) {
		cd, err := g.HubClusters(ctx)
		if err != nil {
			t.Fatal(err)
		}
		log.Println(cd)
	})

	t.Run("secret", func(t *testing.T) {
		cd, err := GetSecret(ctx, tok, g.ProjectID, "ca", "1")
		if err != nil {
			t.Log(err)
		}
		log.Println(string(cd))
	})

	// Init the CA - this normally runs on a remote server with ACME certs.
	ca := certs.NewCerts()
	ca.BaseDir = "../../testdata/ca"
	err = ca.Provision(ctx)
	if err != nil {
		t.Fatal(err)
	}

	mauth := ca.NewID("istio-system", "istiod", nil)

	laddr := startServer(t, ca, mauth)
	mdsc := &MDS{
		Addr: "http://" + laddr + "/computeMetadata/v1",
	}

	_, err = mdsc.GetToken(ctx, "http://foo.com")
	if err != nil {
		t.Fatal("getting token from MDS", err)
	}

	mdsc1 := New()
	mdsc1.Provision(ctx)
	// Use the private CA server to get a token and initialize a client
	istio_ca, err := mdsc1.GetToken(ctx, "istio-ca")
	if err != nil {
		t.Fatal(err)
	}
	checkJWT(t, istio_ca)

}

func checkJWT(t *testing.T, jwt string) {

	r, _ := http.NewRequest("GET", "http://example", nil)
	// Expired key - issue a new one
	r.Header["Authorization"] = []string{"bearer " + jwt}

	// Example of google JWT in cloudrun:
	// eyJhbGciOiJSUzI1NiIsImtpZCI6IjBlNzJkYTFkZjUwMWNhNmY3NTZiZjEwM2ZkN2M3MjAyOTQ3NzI1MDYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIzMjU1NTk0MDU1OS5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1ZCI6IjMyNTU1OTQwNTU5LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTA0MzY2MjYxNjgxNjMwMTM4NTIzIiwiZW1haWwiOiJjb3N0aW5AZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJ1MTIwMzhrTTh2THcyZGN0dnVvbTdBIiwiaWF0IjoxNzAwODg0MDAwLCJleHAiOjE3MDA4ODc2MDB9.SIGNATURE_REMOVED_BY_GOOGLE"

	cfg := &tokens.AuthnConfig{}

	cfg.Issuers = []*tokens.TrustConfig{{Issuer: "https://accounts.google.com"}}

	ja := cfg.New()

	// May use a custom method too with lower deps
	//ja.Verify = oidc.Verify

	_, err := ja.Auth(r)
	if err != nil {
		t.Fatal(err)
	}
}

func startServer(t *testing.T, ca *certs.Certs, mauth *certs.Cert) string {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 0})
	if err != nil {
		t.Fatal("Listen")
	}
	_, p, _ := net.SplitHostPort(l.Addr().String())
	addr := fmt.Sprintf("localhost:%s", p)

	authn := (&tokens.AuthnConfig{
		Issuers: []*tokens.TrustConfig{
			&tokens.TrustConfig{
				Issuer: "http://" + addr,
			},
			&tokens.TrustConfig{
				Issuer: "http://ca",
				Jwks:   tokens.GetJWK(ca.Private),
			},
		},
	}).New()
	// An STS server returning tokens signed by the CA.
	sts := &tokens.TokenExchangeD{
		Authn: authn,
		Generate: func(ctx context.Context, jwt *tokens.JWT, aud string) (string, error) {
			return tokens.GetToken(ctx, ca.Private, "test", aud, "")
		},
	}

	mux := &http.ServeMux{}

	mux.Handle("/v1/token", sts)

	mdd := NewServer()
	mdd.Mux = mux
	mdd.Start()

	ca.Provision(context.Background())

	// An MDS server should be able to proxy OIDC and know/cache JWK.

	// TODO: init a per-node intermediate CA that can sign tokens for the node or cluster.

	go http.Serve(l, mux)

	return addr
}
