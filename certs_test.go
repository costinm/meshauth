package meshauth

import (
	"testing"
)

func TestCerts(t *testing.T) {
	// New self-signed root CA
	ca := NewCA("")
	ca.Save("../test/testdata/tmp/ca")

	// Sign the certs and create the identities for the 2 workloads.
	aliceID := ca.NewID("alice", "default")
	aliceID.SaveCerts("../test/testdata/tmp/alice")

}
