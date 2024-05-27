package test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/costinm/meshauth"
	"github.com/costinm/meshauth/pkg/stsd"
)

func TestJWKS(t *testing.T) {
	ctx := context.Background()

	// Init the CA - this normally runs on a remote server with ACME certs.
	ca := meshauth.CAFromEnv("../testdata/ca")

	mauth := ca.NewID("istio-system", "istiod", nil)

	laddr := startServer(t, ca, mauth)
	// TODO: start an auth server

	cfg := &meshauth.AuthnConfig{
		Issuers: []*meshauth.TrustConfig{
			&meshauth.TrustConfig{
				Issuer: "https://accounts.google.com",
			},
			&meshauth.TrustConfig{
				Issuer: "https://container.googleapis.com/v1/projects/costin-asm1/locations/us-central1-c/clusters/big1",
			},
			//&TrustConfig{
			//	Issuer: laddr,
			//},
		},
	}
	ja := meshauth.NewAuthn(cfg)

	l := &meshauth.TrustConfig{
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
	t.Log(cfg.Issuers)

	// Client tests
	ctx, cf := context.WithTimeout(context.Background(), 5*time.Second)
	defer cf()

	// Will get K8S tokens to authenticate, with istio-ca audience
	stsc := meshauth.NewFederatedTokenSource(&meshauth.STSAuthConfig{
		STSEndpoint: "http://" + laddr + "/v1/token",
		TokenSource: ca, // def.NewK8STokenSource("istio-ca"),
	})

	_, err = stsc.GetToken(ctx, "http://foo.com")
	if err != nil {
		t.Fatal("STSc token ", err)
	}

	mdsc := &meshauth.MDS{
		Addr: "http://" + laddr + "/computeMetadata/v1",
	}

	_, err = mdsc.GetToken(ctx, "http://foo.com")
	if err != nil {
		t.Fatal("getting token from MDS", err)
	}

	// Use the private CA server to get a token and initialize a client
	istio_ca, err := mauth.MDS.GetToken(ctx, "istio-ca")
	if err != nil {
		t.Fatal(err)
	}
	checkJWT(t, istio_ca)

}

// startServer will start a basic XMDS server, with deps-free packages.
// - ca and JWT signing - using testdata
// - local metadata server
//
// TODO: alternative is to run xmdsd in testdata dir.
func startServer(t *testing.T, ca *meshauth.CA, mauth *meshauth.MeshAuth) string {
	l, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 0})
	if err != nil {
		t.Fatal("Listen")
	}
	_, p, _ := net.SplitHostPort(l.Addr().String())
	addr := fmt.Sprintf("localhost:%s", p)

	authn := meshauth.NewAuthn(&meshauth.AuthnConfig{
		Issuers: []*meshauth.TrustConfig{
			&meshauth.TrustConfig{
				Issuer: "http://" + addr,
			},
		},
	})
	// An STS server returning tokens signed by the CA.
	sts := &stsd.TokenExchangeD{
		Authn: authn,
		Generate: func(ctx context.Context, jwt *meshauth.JWT, aud string) (string, error) {
			return ca.GetToken(ctx, aud)
		},
	}

	mds := &meshauth.MDS{}

	mux := &http.ServeMux{}

	mux.Handle("/v1/token", sts)

	mux.HandleFunc("/computeMetadata/v1/", mds.HandleMDS)
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

	cfg := &meshauth.AuthnConfig{}

	cfg.Issuers = []*meshauth.TrustConfig{{Issuer: "https://accounts.google.com"}}

	ja := meshauth.NewAuthn(cfg)

	// May use a custom method too with lower deps
	//ja.Verify = oidc.Verify

	err := ja.Auth(nil, r)
	if err != nil {
		t.Fatal(err)
	}
}

// ========== Old VAPID JWT tests =============

const (
	testpriv = "bSaKOws92sj2DdULvWSRN3O03a5vIkYW72dDJ_TIFyo"
	testpub  = "BALVohWt4pyr2L9iAKpJig2mJ1RAC1qs5CGLx4Qydq0rfwNblZ5IJ5hAC6-JiCZtwZHhBlQyNrvmV065lSxaCOc"
)

func TestVapid(t *testing.T) {
	rfcEx := "vapid t=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3B1c2guZXhhbXBsZS5uZXQiLCJleHAiOjE0NTM1MjM3NjgsInN1YiI6Im1haWx0bzpwdXNoQGV4YW1wbGUuY29tIn0.i3CYb7t4xfxCDquptFOepC9GAu_HLGkMlMuCGSK2rpiUfnK9ojFwDXb1JrErtmysazNjjvW2L9OkSSHzvoD1oA, " +
		"k=BA1Hxzyi1RUM1b5wjxsn7nGxAszw2u61m164i3MrAIxHF6YK5h4SDYic-dRuU_RCPCfA5aq9ojSwk5Y2EmClBPs"

	rfcT, rfcP, err := meshauth.CheckVAPID(rfcEx, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range rfcT.Aud {
		if a != "https://push.example.net" {
			t.Fatal("Aud got ", rfcT.Aud)
		}
	}
	log.Println(len(rfcP), rfcT)

	alice := meshauth.NewMeshAuth(&meshauth.MeshCfg{
		Domain: "test.sender"}).InitSelfSigned("")

	bobToken := alice.VAPIDToken("bob")
	log.Println("Authorization: " + bobToken)

	tok, pub, err := meshauth.CheckVAPID(bobToken, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	log.Println(len(pub), tok)

	btb := []byte(bobToken)
	btb[50]++
	bobToken = string(btb)
	_, _, err = meshauth.CheckVAPID(bobToken, time.Now())
	if err == nil {
		t.Fatal("Expecting error")
	}

}

func TestSigFail(t *testing.T) {
	payload := `{"UA":"22-palman-LG-V510-","IP4":"10.1.10.223"}`
	log.Println(payload)

	payloadhex, _ := hex.DecodeString("7b225541223a2232322d70616c6d616e2d4c472d563531302d222c22495034223a2231302e312e31302e323233227d0a9d4eda35ad1bba104bfee8f92c3d602ceb6f53754a499e28d5569c5a7173b2c100f9a1d4d19f1154cf2699df676fcd63ddd3bf6cd5e1a4db9bccceec262c0be1")
	log.Println(string(payloadhex[0 : len(payloadhex)-64]))

	//BJ1O2jWtG7oQS/7o+Sw9YCzrb1N1SkmeKNVWnFpxc7LBAPmh1NGfEVTPJpnfZ2/NY93Tv2zV4aTbm8zO7CYsC+E=
	log.Println("Pub:", hex.EncodeToString(payloadhex[len(payloadhex)-64:]))
	log.Println("Pub:", "9d4eda35ad1bba104bfee8f92c3d602ceb6f53754a499e28d5569c5a7173b2c100f9a1d4d19f1154cf2699df676fcd63ddd3bf6cd5e1a4db9bccceec262c0be1")
	//buf := bytes.RBuffer{}
	//buf.Write(payloadhex)
	//buf.Write(pub)

	hasher := crypto.SHA256.New()
	hasher.Write(payloadhex) //[0:64]) // only public key, for debug
	hash := hasher.Sum(nil)
	log.Println("SHA:", hex.EncodeToString(hash))

	sha := "a2fe666ae95fe8b7c05bfb0215c9d58fe2121ec0baef70de8cc5fd10d15a3e9c"
	log.Println("SHA:", sha)

	sig, _ := hex.DecodeString("9930116d656c7b977a46ca948eb7c49f0fe9b4fe11ae3790bbd8ed47d71135278ddda2d3f9b1aafdad08a14e38b5fc71e41527b0aecda7ce307ef23a8f0f8ee1")

	ok := meshauth.Verify(payloadhex, payloadhex[len(payloadhex)-64:], sig)
	log.Println(ok)

}

func TestSig(t *testing.T) {
	pubb, _ := base64.RawURLEncoding.DecodeString(testpub)
	priv, _ := base64.RawURLEncoding.DecodeString(testpriv)
	d := new(big.Int).SetBytes(priv)

	log.Println("Pub: ", hex.EncodeToString(pubb))
	x, y := elliptic.Unmarshal(Curve256, pubb)
	pubkey := ecdsa.PublicKey{Curve: Curve256, X: x, Y: y}

	pkey := ecdsa.PrivateKey{PublicKey: pubkey, D: d}

	hasher := crypto.SHA256.New()
	hasher.Write(pubb[1:65])
	hash := hasher.Sum(nil)
	log.Println("HASH: ", hex.EncodeToString(hash))

	r, s, _ := ecdsa.Sign(rand.Reader, &pkey, hash)
	rBytes := r.Bytes()
	rBytesPadded := make([]byte, 32)
	copy(rBytesPadded[32-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, 32)
	copy(sBytesPadded[32-len(sBytes):], sBytes)
	sig := append(rBytesPadded, sBytesPadded...)

	log.Println(pubkey)

	log.Println("R:", hex.EncodeToString(r.Bytes()), hex.EncodeToString(s.Bytes()))

	err := meshauth.Verify(pubb[1:65], pubb[1:65], sig)
	if err != nil {
		t.Error(err)
	}
}

var Curve256 = elliptic.P256()

// ~31us on amd64/2G
func BenchmarkSig(b *testing.B) {
	pubb, _ := base64.RawURLEncoding.DecodeString(testpub)
	priv, _ := base64.RawURLEncoding.DecodeString(testpriv)
	d := new(big.Int).SetBytes(priv)
	x, y := elliptic.Unmarshal(Curve256, pubb)
	pubkey := ecdsa.PublicKey{Curve: Curve256, X: x, Y: y}
	pkey := ecdsa.PrivateKey{PublicKey: pubkey, D: d}

	for i := 0; i < b.N; i++ {
		hasher := crypto.SHA256.New()
		hasher.Write(pubb[1:65])
		ecdsa.Sign(rand.Reader, &pkey, hasher.Sum(nil))
	}
}

// 2us
func BenchmarkVerify(b *testing.B) {
	pubb, _ := base64.RawURLEncoding.DecodeString(testpub)
	priv, _ := base64.RawURLEncoding.DecodeString(testpriv)
	d := new(big.Int).SetBytes(priv)
	x, y := elliptic.Unmarshal(Curve256, pubb)
	pubkey := ecdsa.PublicKey{Curve: Curve256, X: x, Y: y}
	pkey := ecdsa.PrivateKey{PublicKey: pubkey, D: d}
	hasher := crypto.SHA256.New()
	hasher.Write(pubb[1:65])
	r, s, _ := ecdsa.Sign(rand.Reader, &pkey, hasher.Sum(nil))
	rBytes := r.Bytes()
	rBytesPadded := make([]byte, 32)
	copy(rBytesPadded[32-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, 32)
	copy(sBytesPadded[32-len(sBytes):], sBytes)
	sig := append(rBytesPadded, sBytesPadded...)

	for i := 0; i < b.N; i++ {
		meshauth.Verify(pubb, pubb, sig)
	}
}

func TestXFCC(t *testing.T) {
	vals := meshauth.ParseXFCC(`By=spiffe://cluster.local/ns/ssh-ca/sa/default;Hash=8813da93b;Subject="";URI=spiffe://cluster.local/ns/sshd/sa/default`)
	if vals["By"] != "spiffe://cluster.local/ns/ssh-ca/sa/default" {
		t.Error("Missing By")
	}

	if vals["URI"] != "spiffe://cluster.local/ns/sshd/sa/default" {
		t.Error("Missing URI")
	}

}
