package certs

import (
	"context"
	"crypto/tls"
	"encoding/asn1"
	"encoding/json"
	"log"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"
)

func TestCerts(t *testing.T) {

	base := "" // /tmp" // set to "" to replace the canonical files

	ctx := context.Background()

	t.Run("Init", func(t *testing.T) {
		// New self-signed root CA
		ca := NewCerts()
		ca.FQDN = "test.mesh.local"
		ca.Provision(ctx)
		ca.Save(nil, base+"../../testdata/ca")

		cai := ca.NewIntermediaryCA("test.mesh.local", "cluster1")
		cai.Save(nil, base+"../../testdata/cluster1")
	})

	t.Run("Load", func(t *testing.T) {
		// New self-signed root CA
		ca := NewCerts()
		ca.Base = base + "../../testdata/ca"
		ca.Provision(context.Background())

		ca1 := NewCerts()
		ca1.Base = base + "../../testdata/cluster1"
		ca.Provision(context.Background())
	})

	certs := NewCerts()
	// self-init
	err := certs.Provision(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// SetCert the test CAs
	ca := NewCerts()
	ca.Init("../../testdata/ca")
	if ca.Private == nil {
		t.Fatal("Failed to load CA")
	}

	cai := ca.NewIntermediaryCA("test.mesh.local", "cluster1")
	cai.Save(nil, base+"../../testdata/cluster1")

	cai = NewCerts()
	err = cai.Init("../../testdata/cluster1")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("SaveCerts", func(t *testing.T) {
		// Sign the certs and create the identities for the 2 workloads.
		aliceID := ca.NewID("alicens", "alicesa", []string{"alicesvc.alicens.svc.test.mesh.local"})
		aliceID.Save(nil, base+"testdata/alice")

		// For bob, use cluster1 intermediate CA
		bobID := cai.NewID("bobns", "bob", []string{"bob.bobns.svc.test.mesh.local",
			"bob.example.com"})
		bobID.Save(nil, base+"testdata/bob")
	})
}

func TestCertsBase(t *testing.T) {
	ctx := context.Background()

	// Create a new root CA - no base dir.
	ca := NewCerts()

	// No settings - will generate a self-signed root CA.
	ca.Provision(ctx)

	if ca.Private == nil {
		t.Errorf("Missing root key")
	}

	cab, _ := json.MarshalIndent(ca, " ", " ")
	t.Log(string(cab))

	t.Run("Create cert", func(t *testing.T) {
		crt, _, _ := ca.NewTLSCert("istio-system", "istiod",
			[]string{"istiod.istio-system.svc.internal"})

		// We now have a cert signed directly by the root.
		if crt != nil {
			t.Error("Failed to create crt")
		}

	})

	caEx := NewCerts()
	ca.BaseDir = "../../testdata/ca"
	err := ca.Provision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cab, _ = json.MarshalIndent(caEx, " ", " ")
	t.Log(string(cab))

}

func TestHome(t *testing.T) {
	ctx := context.Background()
	home, _ := os.UserHomeDir()

	// Root CA stored in user home, next to .ssh keys
	ca := NewCerts()
	ca.BaseDir = home + ".ssh"
	ca.Provision(ctx)

	id1 := ca.NewID("istio-system", "istiod", nil)
	id1.Save(ctx, ca.BaseDir+"/istio-system/istiod")

	crt1 := NewCert()
	crt1.Provision(ctx)

}

// Debug the chain:
// openssl crl2pkcs7 -nocrl -certfile bob/certificates.pem | openssl pkcs7 -print_certs -text -noout

func TestCertsTLS(t *testing.T) {
	// SetCert the test CAs
	ca := NewCerts()
	ca.Init("../../testdata/ca")
	if ca.Private == nil {
		t.Fatal("Failed to load CA")
	}

	cai := NewCerts()
	cai.Init("../../testdata/cluster1")

	ctx := context.Background()

	// Both alice and bob have the same root CA
	alice := NewCert()
	alice.Base = "testdata/alice"
	alice.Provision(ctx)
	//		Domain:         "test.mesh.local",

	bob := NewCert()
	bob.Base = "testdata/bob"
	bob.Provision(ctx)

	//		AllowedNamespaces: []string{"alicens"},

	// Self-signed certificate, no CA, chain has 1 element.
	aliceExt := NewCert()
	aliceExt.Provision(ctx)

	// Self-signed cert, no CA roots to verify clients
	bobExt := NewCert()
	bobExt.Provision(ctx)

	//log.Println("Alice: ", alice.TrustDomain, alice)

	//log.Println("Bob: ", bob.TrustDomain, bob)

	tcs := TestingNewPair()
	sb := make([]byte, 1024)

	// Server trusting external clients
	trustExt := &MeshTrust{
		AllowMeshExternal: true,
	}

	// Trust specifically bob
	trustBob := &Trust{
		AllowMeshExternal: true,
		ALPN:              []string{"alpn1", "h2"}, SNI: "bobsni",
	}
	trustBob2 := &Trust{
		AllowMeshExternal: true,
		URLSANs: []string{
			"spiffe://test.mesh.local/ns/bobns/sa/bobsa",
		},
		ALPN: []string{"alpn1", "h2"}, SNI: "bob.bobns.svc.test.mesh.local",
	}

	trustAlice := &Trust{
		AllowMeshExternal: true,
		ALPN:              []string{"alpn1", "h2"}, SNI: "bobsni",
	}

	// Handshake without requiring public roots
	t.Run("HandshakeAllowExternal", func(t *testing.T) {
		// If same config is used, session tickets enabled
		serverTLSConfg := bobExt.GenerateTLSConfigServer(trustExt)

		clientTLSConfig := aliceExt.TLSClientConf(trustBob, "", bobExt.PubB32(), trustExt)

		tlsc, tlss := tcs.testingTLSPair(ctx, t, serverTLSConfg, clientTLSConfig, sb)

		check(t, tlss, nil, trustExt)

		// IMPORTANT: tls session in 1.3 is in a post-handshake message from server.
		// That is called in client.Read
		check(t, tlsc, nil, trustExt)

		tlsc, tlss = tcs.testingTLSPair(ctx, t, serverTLSConfg, clientTLSConfig, sb)

		check(t, tlsc, nil, trustExt)

		check(t, tlss, nil, trustExt)
		log.Println(trustExt.ClientSessionCache)
	})

	t.Run("Handshake", func(t *testing.T) {
		serverTLSConfg := bob.GenerateTLSConfigServer(trustExt)

		clientTLSConfig := alice.TLSClientConf(trustBob2, "", "", trustExt)
		tlsc, tlss := tcs.testingTLSPair(ctx, t, serverTLSConfg, clientTLSConfig, sb)

		check(t, tlss, trustAlice, nil)
		check(t, tlsc, trustBob, nil)

		tlsc, tlss = tcs.testingTLSPair(ctx, t, serverTLSConfg, clientTLSConfig, sb)
		check(t, tlsc, trustBob, nil)
		check(t, tlss, trustAlice, nil)

		log.Println(trustBob2.ClientSessionCache)
		if !tlss.ConnectionState().DidResume {
			t.Error("Connection not reused")
		}

		clientTLSConfig = alice.TLSClientConf(trustBob2, "bob.bobns.svc.test.mesh.local", "", trustExt)
		tlsc, tlss = tcs.testingTLSPair(ctx, t, serverTLSConfg, clientTLSConfig, sb)
		check(t, tlsc, trustBob2, nil)
		check(t, tlss, trustAlice, nil)

		// Again with spiffe
		tlsc, tlss = tcs.testingTLSPair(ctx, t, serverTLSConfg, clientTLSConfig, sb)
		check(t, tlss, trustAlice, trustExt)
		check(t, tlsc, trustBob2, trustExt)

		tlsc, tlss = tcs.testingTLSPair(ctx, t, serverTLSConfg, clientTLSConfig, sb)

		check(t, tlsc, trustBob2, trustExt)

		check(t, tlss, trustAlice, trustExt)
		log.Println(trustBob2.ClientSessionCache)

	})
}

// Check verifies and log the TLS connection
func check(t *testing.T, tlss *tls.Conn, ext *Trust, mesh *MeshTrust) {
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
		PublicKeyBase32SHA(c[0].PublicKey))

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

// DER JSON mapping
// - composites: SQEUENCE == list and map (key/value sequence)
// - primitives: octet string, int

type DJSON struct {
	// If first field is asn1.RawContent - it is set with the raw value

	String string `asn1:utf8,tag:1,optional
`
	// Unint8 sequence - gets the value
	Bytes []byte

	// Sequence
	Elem []*DJSON
}

type DER struct {
	// OCTET STRING
	Bytes []byte

	// PrintableString, IA5String, NumericString, UTF8String
	String string `asn1:utf8,tag:1,optional`

	// Boolean set as 1 or 0
	Int int64

	//Map map[string]*DJSON

	// SEQUENCE OF and SET OF (set tag)
	// Can also be saved to a struct.
	//List []interface{}

	// INTEGER is mapped to int or big int.

	//Big *big.Int

	// BIT string type (not aligned to 8-bit)
	Bits asn1.BitString

	// OBJECT IDENTIFIER
	//OID asn1.ObjectIdentifier

	// ENUMERATED
	Enum asn1.Enumerated

	// UTCTIME or GENERALIZEDTIME
	Time time.Time
}

// DER vs CBOR

func TestDER(t *testing.T) {
	t.Run("js", func(t *testing.T) {
		js := `{
		"bytes": "YWJj",
		"string": "abc",
		"int": 123,
		"float": 1.23,
		"map": {
			"key": { "in&t": 123 }
		}
  }`

		jsv := map[string]any{}
		json.Unmarshal([]byte(js), &jsv)
		t.Log(jsv)

		ba, err := asn1.Marshal(jsv)
		if err != nil {
			t.Fatal(err)
		}

		jsv1 := map[string]interface{}{}
		asn1.Unmarshal(ba, jsv1)
		t.Log(jsv1)
	})

	t.Run("gen", func(t *testing.T) {
		djs := DER{
			Bytes:  []byte("abc"),
			String: "abc",
			Int:    123,
		}

		ba, err := asn1.Marshal(djs)
		if err != nil {
			t.Fatal(err)
		}
		// TAG CompoundFlag TAGCLASS LEN
		//

		vi := asn1.RawValue{}
		_, err = asn1.Unmarshal(ba, &vi)
		t.Log(vi.Tag, err)
		// class: 0 (universal)
		// tag: 16 (sequence)
		// isCompound: true
		// Bytes and FullBytes (incl tag)

		rest, err := asn1.Unmarshal(vi.Bytes, &vi)
		t.Log(vi.Tag, err)
		// tag: 4 (octet string)
		// isCompound: false

		rest, err = asn1.Unmarshal(rest, &vi)
		t.Log(vi.Tag, err)
		// tag: 4 (octet string)
		// isCompound: false

		// Unlike json - returns 'rest' as well !
		// Equivalent to CBOR DecodeFirst which leaves in reader the rest.
		_, err = asn1.Unmarshal(ba, &djs)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(djs)
	})
}
