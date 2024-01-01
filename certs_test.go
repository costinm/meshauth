package meshauth

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"testing"

	"log/slog"
)

// Debug the chain:
// openssl crl2pkcs7 -nocrl -certfile bob/certificates.pem | openssl pkcs7 -print_certs -text -noout

func TestCerts(t *testing.T) {
	base := "" // /tmp" // set to "" to replace the canonical files
	t.Run("Save", func(t *testing.T) {
		// New self-signed root CA
		ca := NewTempCA("test.mesh.local") // instead of cluster.local
		ca.Save(base + "testdata/ca")

		cai := ca.NewIntermediaryCA("test.mesh.local", "cluster1")
		cai.Save(base + "testdata/cluster1")
	})

	// Load the test CAs
	ca := CAFromEnv("testdata/ca")

	cai := CAFromEnv("testdata/cluster1")

	t.Run("SaveCerts", func(t *testing.T) {
		// Sign the certs and create the identities for the 2 workloads.
		aliceID := ca.NewID("alicens", "alicesa", []string{"alicesvc.alicens.svc.test.mesh.local"})
		aliceID.SaveCerts(base + "testdata/alice")

		// For bob, use cluster1 intermediate CA
		bobID := cai.NewID("bobns", "bob", []string{"bob.bobns.svc.test.mesh.local",
			"bob.example.com"})
		bobID.SaveCerts(base + "testdata/bob")
	})

	// Both alice and bob have the same root CA
	alice, _ := FromEnv(&MeshAuthCfg{
		CertDir:     "testdata/alice",
		TrustDomain: "test.mesh.local",
	})

	bob, _ := FromEnv(&MeshAuthCfg{
		AllowedNamespaces: []string{"alicens"},
		CertDir:           "testdata/bob",
		TrustDomain:       "test.mesh.local", // bug - fix cert generation for intermdiate
	})

	// Self-signed certificate, no CA, chain has 1 element.
	aliceExt := NewMeshAuth(&MeshAuthCfg{})
	aliceExt.InitSelfSigned("")

	// Self-signed cert, no CA roots to verify clients
	bobExt := NewMeshAuth(&MeshAuthCfg{})
	bobExt.InitSelfSigned("")

	//log.Println("Alice: ", alice.TrustDomain, alice)

	//log.Println("Bob: ", bob.TrustDomain, bob)

	tcs := TestingNewPair()
	ctx := context.Background()
	sb := make([]byte, 1024)

	// Handshake without requiring public roots
	t.Run("HandshakeAllowExternal", func(t *testing.T) {
		// If same config is used, session tickets enabled
		serverTLSConfg := bobExt.GenerateTLSConfigServer(true)
		clientTLSConfig := aliceExt.TLSClientConf(&Dest{
			ALPN: []string{"alpn1", "h2"},
		}, "bobsni", bobExt.ID)

		tlsc, tlss := tcs.testingTLSPair(ctx, t, serverTLSConfg, clientTLSConfig, sb)

		check(t, tlss, aliceExt)

		// IMPORTANT: tls session in 1.3 is in a post-handshake message from server.
		// That is called in client.Read
		check(t, tlsc, bobExt)

		tlsc, tlss = tcs.testingTLSPair(ctx, t, serverTLSConfg, clientTLSConfig, sb)

		check(t, tlsc, bobExt)

		check(t, tlss, aliceExt)
		log.Println(aliceExt.ClientSessionCache)
	})

	t.Run("Handshake", func(t *testing.T) {
		serverTLSConfg := bob.GenerateTLSConfigServer(true)

		clientTLSConfig := alice.TLSClientConf(&Dest{}, "bob.bobns.svc.test.mesh.local", "")
		tlsc, tlss := tcs.testingTLSPair(ctx, t, serverTLSConfg, clientTLSConfig, sb)

		check(t, tlss, alice)
		check(t, tlsc, bob)

		tlsc, tlss = tcs.testingTLSPair(ctx, t, serverTLSConfg, clientTLSConfig, sb)
		check(t, tlsc, bob)
		check(t, tlss, alice)

		log.Println(alice.ClientSessionCache)
		if !tlss.ConnectionState().DidResume {
			t.Error("Connection not reused")
		}

		bobDest := &Dest{URLSANs: []string{
			"spiffe://test.mesh.local/ns/bobns/sa/bobsa",
		}}
		clientTLSConfig = alice.TLSClientConf(bobDest, "bob.bobns.svc.test.mesh.local", "")
		tlsc, tlss = tcs.testingTLSPair(ctx, t, serverTLSConfg, clientTLSConfig, sb)
		check(t, tlsc, bob)
		check(t, tlss, alice)

		// Again with spiffe
		tlsc, tlss = tcs.testingTLSPair(ctx, t, serverTLSConfg, clientTLSConfig, sb)
		check(t, tlss, alice)
		check(t, tlsc, bob)

		tlsc, tlss = tcs.testingTLSPair(ctx, t, serverTLSConfg, clientTLSConfig, sb)

		check(t, tlsc, bob)

		check(t, tlss, alice)
		log.Println(alice.ClientSessionCache)

	})
}

func check(t *testing.T, tlss *tls.Conn, ext *MeshAuth) {
	if tlss == nil {
		t.Fatal("Failed server handshake")
	}
	ccs := tlss.ConnectionState()

	// All we get in connection state...
	slog.Info("Client", "sni", ccs.ServerName,
		"alpn", ccs.NegotiatedProtocol,
		"peerCerts", ccs.PeerCertificates,
		"verifiedChains", ccs.VerifiedChains,
		"version", ccs.Version,
		"cipher", ccs.CipherSuite,
		"resume", ccs.DidResume)

	// len = 1 means self-signed cert.
	c := ccs.PeerCertificates
	log.Println("Client received certs",
		len(c), c[0].URIs, c[0].DNSNames,
		PublicKeyBase32SHA(c[0].PublicKey), ext.ID)

}

func serverHandshake(ctx context.Context, ss net.Conn, server *tls.Config) chan *tls.Conn {
	sch := make(chan *tls.Conn)
	go func() {

		tlss := tls.Server(ss, server)
		err := tlss.HandshakeContext(ctx)
		if err != nil {
			sch <- nil
			log.Println("Failed server hs")
			return
		}
		sch <- tlss
	}()
	return sch
}

type TestingClientServer struct {
	Listener net.Listener
}

func (s *TestingClientServer) Pair() (net.Conn, net.Conn) {
	cs, err := net.Dial("tcp", s.Listener.Addr().String())
	if err != nil {
		panic(err)
	}
	ss, err := s.Listener.Accept()
	if err != nil {
		panic(err)
	}
	return cs, ss
}

func (tcs *TestingClientServer) testingTLSPair(ctx context.Context, t *testing.T, serverTLSConfg *tls.Config,
	clientTLSConfig *tls.Config, clientBuf []byte) (*tls.Conn, *tls.Conn) {
	cs, ss := tcs.Pair()
	sch := serverHandshake(ctx, ss, serverTLSConfg)
	tlsc := tls.Client(cs, clientTLSConfig)
	var err error
	if err = tlsc.HandshakeContext(ctx); err != nil {
		// if the context was canceled, return the context error
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = ctxErr
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	tlss := <-sch

	if tlss == nil {
		t.Fatal("Server handshake failed")
	}

	tlsc.Write([]byte("hi"))
	n, err := tlss.Read(clientBuf)
	if n != 2 {
		t.Fatal("")
	}
	tlss.Write([]byte("hi"))
	n, err = tlsc.Read(clientBuf)
	if n != 2 {
		t.Fatal("")
	}

	return tlsc, tlss
}

func TestingNewPair() *TestingClientServer {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}

	return &TestingClientServer{
		Listener: l,
	}
}
