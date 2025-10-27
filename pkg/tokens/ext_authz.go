package tokens

import (
	"fmt"
	"log/slog"
	"net/http"
)

// External authz rules - support subset of Istio API.
type Authz struct {
}

// Envoy ExtAuthz uses the original URL path - but there is a header.
// For same host, we may identify the caller by IP, using MDB and same host.
//
// Ext Authz can be used for both authn and authz. 'include_peer_certificate' can
// get the peer cert.
//
// TODO: actual code - for now just dump.
func (*Authz) ServeHTTP(writer http.ResponseWriter, request *http.Request) {

	//  X-Envoy-Expected-Rq-Timeout-Ms:[250] X-Envoy-Internal:[true]
	if request.Header.Get("X-Authz-Header1") != "" {
		// "headers":{"Content-Length":["0"],
		// "X-Authz-Header1":["value"],
		// "X-Authz-Header2":["value2"],

		// "X-Envoy-Expected-Rq-Timeout-Ms":["1000"],
		// "X-Envoy-Internal":["true"],
		// "X-Forwarded-For":["192.168.1.115"]},
		// "method":"GET",
		// "uri":{"Scheme":"","Opaque":"","User":null,"Host":"","Path":"/","RawPath":"",
		// "OmitHost":false,"ForceQuery":false,"RawQuery":"","Fragment":"","RawFragment":""}}
		slog.Info("ext_authz request", "headers", request.Header, "method", request.Method,
			"uri", request.URL)
		writer.WriteHeader(200)

		// Metadata added under envoy.filters.http.ext_authz - based on prefix
		// Other meta: ext_authz_duration
		// Prefix is included in the key name, no need for dots
		// due to prefix costin
		writer.Header().Add("costin-authz", "testdynamic2")

		writer.Header().Add("Authorization", "Bearer foo-bar")

		// experimenta with the headers
		writer.Header().Add("x-authz-test1", "upstream")

		// sent to server
		writer.Header().Add("x-extauthz-test1", "upstream")

		// sent to server
		writer.Header().Add("x-cextauthz-test2", "client")

		writer.Header().Add("x-dextauthz", "client")
		writer.Header().Add("x-dextauthz-test3", "client")

	} else {
		// uri doesn't include host
		slog.Info("echo", "method", request.Method, "host", request.Host,
			"uri", request.URL.Path, "q", request.URL.RawQuery,
			"xfh", request.Header["X-Forwarded-Host"],
			"xff", request.Header["X-Forwarded-For"],
			"headers", request.Header)

		writer.WriteHeader(200)
		writer.Write([]byte(fmt.Sprintf("%v", request)))

	}
}
