package mhttp

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/costinm/meshauth"
	"github.com/costinm/meshauth/pkg/tokens"
)

// Handler wraps another handler with authn and authz functions.
//
// With otel, this is already wrapped in a telemetry wrapper, ctx can be used for tracing.
// The otel http instrumentation currently doesn't allow other interactions.
type AuthHandlerWrapper struct {
	// Original handler
	Handler http.Handler

	// Authn function
	Auth *tokens.Authn

	// The wrapper will use this to log events and errors.
	Logger *slog.Logger
}

func NewAuthHandler(mesh *meshauth.Mesh, mux *http.ServeMux) http.Handler {
	var h http.Handler
	h = &AuthHandlerWrapper{
		Handler: mesh.Mux,
		Logger:  slog.With("id", mesh.Name),
	}
	// This is for telemetry - in front of auth so auth can trace ?
	// or after ? Might be better to inject tracer here.
	if mesh.HandlerWrapper != nil {
		// TODO: wrap individual handlers added to the mux instead.
		h = mesh.HandlerWrapper(h, mesh.Name)
	}
	return h
}

// Entry point for H1, H2 - will delegate to the real handler after authenticating.
// Also keeps track of the request time and logs the request.
func (h *AuthHandlerWrapper) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	actx := &meshauth.RequestContext{
		Context: request.Context(),

		Start: time.Now(),
	}

	// TODO: All logs for this request have the URL and trace ID
	// TODO: only first part or some filter for high cardinality metrics and long log lines.
	actx.Logger = h.Logger.With("url", request.URL)

	var RemoteID string
	var SAN string

	defer func() {
		// TODO: add it to an event buffer
		if h.Logger != nil {
			h.Logger.InfoContext(request.Context(), "REQUEST",
				"remoteID", RemoteID,
				"SAN", SAN,
				"request", request.URL, "time", time.Since(actx.Start))
		}
		if r := recover(); r != nil {
			// TODO: this should go to utel tracing (via slog interface)
			h.Logger.Info("Recover", "err", r)

			debug.PrintStack()

			// find out exactly what the error was and set err
			var err error

			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("Unknown panic")
			}
			if err != nil {
				fmt.Println("ERRROR: ", err)
			}
		}
	}()
	// 1. Authenticate the request (or extract auth from sidecar in front)
	//

	if h.Auth != nil {
		err := h.Auth.Auth(actx, request)
		if err != nil {
			log.Println("Failed auth", err, request.Header)
			writer.WriteHeader(403)
			return
		}
	}

	tls := request.TLS
	// If the request was handled by normal uGate listener.
	//us := r.Context().Value("nio.Stream")
	//if ugs, ok := us.(nio.Stream); ok {
	//	tls = ugs.TLSConnectionState()
	//	r.TLS = tls
	//}

	// other keys in a normal request context:
	// - http-server (*http.Server)
	// - local-addr - *net.TCPAddr

	if tls != nil && len(tls.PeerCertificates) > 0 {
		pk1 := tls.PeerCertificates[0].PublicKey
		RemoteID = meshauth.PublicKeyBase32SHA(pk1)
		// TODO: Istio-style, signed by a trusted CA. This is also for SSH-with-cert
		sans, _ := meshauth.GetSAN(tls.PeerCertificates[0])
		if len(sans) > 0 {
			SAN = sans[0]
		}
	}

	// Using the 'from' header internally -
	if RemoteID != "" {
		request.Header.Set("from", RemoteID)
	} else {
		request.Header.Del("from")
	}

	// 2. (opt) authorize if it didn't have a sidecar/waypoint in front

	// 3. Extract/add telemetry data
	//log.Println("Serve HTTP wrapper ", request.Header)

	// Only way to pass a context is by wrapping the request.
	// We could also do a "with" - but that also requires wrapping, there is no update.
	h.Handler.ServeHTTP(writer, request.WithContext(actx))
}

