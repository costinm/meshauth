// tokens implements helpers around signed and auth tokens
package tokens

import (
	"context"
	"crypto"
)

// This package should have no deps outside standard library.
// Its focus is on auth tokens, it includes few exchange protocols.
//
// For getting tokens, the TokenSource interface is used. Different sources
// are available, each generating tokens issued by specific providers.
// A built-in issuer is included, as well as http handlers for a subset of
// OIDC endpoints.
//
// For validation, a subset of OIDC is implemented.
//
// Also included (minimal) STS client and server, GCP MDS client and server
// providing local MDS.
//
// The package is in part based on code or ideas from Istio.

type Tokens struct {

	// Private is the primary identity used by the workload to sign its own
	// tokens.
	//
	// The tokens package can delegate to TokenProviders or generate
	// its own tokens, each workload can act as an OIDC provider.
	//
	// Currently only EC256 is used.
	Private crypto.PrivateKey
}

// PerRPCCredentials defines the common interface for the credentials which need to
// attach security information to every RPC (e.g., oauth2).
// This is the interface used by gRPC - should be implemented by all TokenSource to
// allow use with gRPC.
type PerRPCCredentials interface {
	// GetRequestMetadata gets the current request metadata, refreshing
	// tokens if required. This should be called by the transport layer on
	// each request, and the data should be populated in headers or other
	// context. If a status code is returned, it will be used as the status
	// for the RPC. uri is the URI of the entry point for the request.
	// When supported by the underlying implementation, ctx can be used for
	// timeout and cancellation. Additionally, RequestInfo data will be
	// available via ctx to this call.
	// TODO(zhaoq): Define the set of the qualified keys instead of leaving
	// it as an arbitrary string.
	GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error)
	// RequireTransportSecurity indicates whether the credentials requires
	// transport security.
	RequireTransportSecurity() bool
}

type PerRPCCredentialsFromTokenSource struct {
	TokenSource
}

func (s *PerRPCCredentialsFromTokenSource) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	t, err := s.GetToken(ctx, uri[0])
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"authorization": "Bearer " + t,
	}, nil
}

func (s *PerRPCCredentialsFromTokenSource) RequireTransportSecurity() bool { return false }
