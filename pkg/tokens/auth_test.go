package tokens

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)


func TestJWKS(t *testing.T) {
	ctx := context.Background()
	privk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	laddr := startServer(t, privk)
	// TODO: start an auth server

	cfg := &AuthnConfig{
		Issuers: []*TrustConfig{
			&TrustConfig{
				Issuer: "https://accounts.google.com",
			},
			&TrustConfig{
				Issuer: "https://container.googleapis.com/v1/projects/costin-asm1/locations/us-central1-c/clusters/big1",
			},
			//&TrustConfig{
			//	Issuer: laddr,
			//},
		},
	}
	ja := cfg.New()

	l := &TrustConfig{
		Issuer: "http://" + laddr,
	}
	err := ja.UpdateKeys(ctx, l)
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
	stsc := NewFederatedTokenSource(&STSAuthConfig{
		STSEndpoint: "http://" + laddr + "/v1/token",
		TokenSource: &CATokenSource{CA: privk, Sub: "test", Iss: "http://ca"}, // def.NewK8STokenSource("istio-ca"),
		AudienceSource: "istio-ca",
	})

	_, err = stsc.GetToken(ctx, "http://foo.com")
	if err != nil {
		t.Fatal("STSc token ", err)
	}


}


func startServer(t *testing.T, privk crypto.PrivateKey) string {

	l, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 0})
	if err != nil {
		t.Fatal("Listen")
	}
	_, p, _ := net.SplitHostPort(l.Addr().String())
	addr := fmt.Sprintf("localhost:%s", p)

	authn := (&AuthnConfig{
		Issuers: []*TrustConfig{
			&TrustConfig{
				Issuer: "http://" + addr,
			},
			&TrustConfig{
				Issuer: "http://ca",
				Jwks:   GetJWK(privk),
			},
		},
	}).New()
	// An STS server returning tokens signed by the CA.
	sts := &TokenExchangeD{
		Authn: authn,
		Generate: func(ctx context.Context, jwt *JWT, aud string) (string, error) {
			return GetToken(ctx, privk, "test", aud, "")
		},
	}

	mux := &http.ServeMux{}

	mux.Handle("/v1/token", sts)


	// An MDS server should be able to proxy OIDC and know/cache JWK.

	// TODO: init a per-node intermediate CA that can sign tokens for the node or cluster.

	go http.Serve(l, mux)

	return addr
}

//func TestXFCC(t *testing.T) {
//	vals := tokens.ParseXFCC(`By=spiffe://cluster.local/ns/ssh-ca/sa/default;Hash=8813da93b;Subject="";URI=spiffe://cluster.local/ns/sshd/sa/default`)
//	if vals["By"] != "spiffe://cluster.local/ns/ssh-ca/sa/default" {
//		t.RecordError("Missing By")
//	}
//
//	if vals["URI"] != "spiffe://cluster.local/ns/sshd/sa/default" {
//		t.RecordError("Missing URI")
//	}
//
//}
