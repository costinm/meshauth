package dns

import (
	"context"
	"log"
	"testing"

	"github.com/libdns/googleclouddns"
	"github.com/libdns/libdns"
)

// Requires an env variable or config file.
func TestLibDNS(t *testing.T) {
	// 52 providers...
	// Std: DNS UPDATE / DNS AXFR - Knot, etc.
	// Best over secure IP (ambinet), DOH/DOT

	// rfc2136 defines TSIG-based upgrade/get/delete.

	// desec.io - free provider

	// googleclouddns - uses env variable or gcp_applications_default, gcp_project
	// It also uses the MDS if detected !

	// acmedns: CNAME for _acme-challenge.DOMAIN
	// https://github.com/joohoi/acme-dns
	r := libdns.Record{}
	log.Println(r)

	ctx := context.Background()
	p := googleclouddns.Provider{Project: "dmeshgate"}
	p.GetRecords(ctx, "webinf.info")
}
