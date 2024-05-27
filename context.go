package meshauth

import (
	"context"
	"log/slog"
	"time"
)

// AuthContext is a Context implementation holding auth info for a request.
type AuthContext struct {
	// Workload auth config
	MeshAuth *MeshAuth

	// Parent
	Context context.Context

	// Slog
	Logger *slog.Logger

	Start time.Time

	// Metrics/Tracing

	// Auth info for this context
	Client string
	Peer   string

	JWTs []*JWT
	// Original IP and metadata.
}

func (a *AuthContext) Deadline() (deadline time.Time, ok bool) {
	return a.Context.Deadline()
}

func (a *AuthContext) Done() <-chan struct{} {
	return a.Context.Done()
}

func (a *AuthContext) Err() error {
	return a.Context.Err()
}

// Value may return the AuthContext, if chained - or one of the fields.
// Otherwise will pass to parent.
func (a *AuthContext) Value(key any) any {
	if key == ContextKey {
		return a
	}
	return a.Context.Value(key)
}

const ContextKey = "meshAuth"

func (ma *MeshAuth) WithContext(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	// WithValue is a struct holding the key and value (any), passing to next context.
	// AuthContext holds multiple things in a map.
	return &AuthContext{MeshAuth: ma, Context: ctx}
	// instead of return context.WithValue(ctx, ContextKey, ma)
}
