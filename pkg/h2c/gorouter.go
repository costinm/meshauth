package h2c

import (
	"context"
	"net/http"
)

type GoRouter struct {

	// The key is a route as defined by go ServerMux.
	// The value can be:
	// - a URL - in which case it's a reverse proxy
	// - a string that is a resource name - in which case it's a Handler
	// Other values like TCP proxy can be defined later.
	Routes        map[string]string

	// The actual mux that is configured. Will be mapped to a H2C/H1 server by
	// default, assuming ambient or secure network.
	Mux           *http.ServeMux

	// ResourceStore is used to resolve resources, is a registry of types and
	// objects. We're looking for handlers.
	ResourceStore ResourceStore
}

type ResourceStore interface {
	Resource(ctx context.Context, name string) (any, error)
}

func (r *GoRouter) WithResourceStore(rs ResourceStore) {
	r.ResourceStore = rs
}
func (r *GoRouter) Provision(ctx context.Context) error {
	for k, v := range r.Routes {
		r.Mux.HandleFunc(k, func(writer http.ResponseWriter, request *http.Request) {
			h, err := r.ResourceStore.Resource(ctx, v)
			if err != nil {
				writer.WriteHeader(500)
				return
			}
			// TODO: if v is http or https - plug in a proxy
			// same for tcp/ssh/etc
			if hh, ok := h.(http.Handler); ok {
				hh.ServeHTTP(writer, request)
			} else {
				writer.WriteHeader(500)
				return
			}
		})
	}
	return nil
}
