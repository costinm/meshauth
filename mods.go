package meshauth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"expvar"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"time"
)

// Mods is a dependency-free file that can be cut and pasted to any project.
// It provides a 'modular monolith' model, based by a module registry.
//
// The registry is based on expvar package - so modules are also exposed for
// debugging, and no structure or var is shared.
//
// A module is a struct implementing a number of interfaces. Few common
// interfaces are  defined in this file - around mesh authentication
// (certs, tokens), telemetry, dialers and listeners, as well as a 'conf' interface.
//
// ModDef is a module definition, including a function that returns
// a new un-configured module. The config will be loaded from a conf source,
// will be unmarshalled into the struct, and Init/Start may be called.
//
// A default conf module will use local json files
// or env vars. Other config modules that load remote config or handle
// other formats.
//
// Inspired from K8S, but simpler and no deps - think of ModDef as a CRD, Mod
// as a CR, the config loaders may use K8S to load the CR. It is different
// from K8S - the CR is not just data, but implements functions.
// The 'namespace' is used to model different isolated 'tenants' in same process,
// each with its own identity and config - should not be common, but it is
// useful for testing.

// AddKnownType adds a type constructor function - similar to AddKnownType in K8S,
// but instead of a blank object (with deep copy and other generated functions) it
// is a 'create un-configured object' function.
//
// The context will hold as values other registered types and modules, as well
// as act as a 'namespace', so a binary can handle multiple 'tenants' (it is also
// useful for tests).
//
// The fn() may return a 'blank' object - but it may also use ctx to locate deps
// and defaults or active configs and fully initialize the resource config.
//
// The resource config may be updated after type creation, either using API or
// unmarshalling additional config on the constructed object. If it implements
// interfaces like Init or Start - they can be called after config is fully done.
//
// In K8S, the function can add all 'known types' in one go - this is broken by
// 'typename', which is the group-version, closer to AddKnownType
func AddKnownType[T any](typeName string, fn func (ctx context.Context, namespace, name string) *T) {
	mm := modMap(DefaultContext, defPrefix)
	v := mm.Get(typeName)
	if v != nil {
		log.Println("module already registered", "name", v)
		debug.PrintStack()
		return
	}
	template := &modDefF[T]{ TypeName: typeName, f: fn}

	mm.Set(typeName, template)
}

const defPrefix = "_moddef"
const modPrefix = "_mod"

type modDefF[T interface{}] struct {
	TypeName string
	f    func(ctx context.Context, namespace, name string) *T
	baseConfig *T

	mods map[string]T
}

func (m modDefF[T]) String() string {
	bg, _ := json.Marshal(m.mods)
	return fmt.Sprintf("%q", bg)
}


// modMap returns the module definition map - it could be implemented as a regular Map, but we want it to be
// visible for troubleshooting and expvar is the simplest and dependency free.
func modMap(ctx context.Context, defPrefix string) *expvar.Map {
	m := expvar.Get(defPrefix)
	if m == nil {
		mm := &expvar.Map{}
		expvar.Publish(defPrefix, mm)
		return mm
	}
	if mm, ok := m.(*expvar.Map); ok {
		return mm
	} else {
		panic("Module definitions impossible, already registered with wrong type " + defPrefix)
	}
}

func RegisterMod[T expvar.Var](ctx context.Context, typeName, namespace, name string, mod T) {
	mm := modMap(ctx, modPrefix)
	v := mm.Get(typeName)
	if v != nil {
		log.Println("module already registered", "name", v)
		debug.PrintStack()
		return
	}

	mm.Set(typeName, mod)
}

func ModSeq2[T any](ctx context.Context, yield func(string, T) bool) {
	mm := modMap(ctx, modPrefix)
	mm.Do(func(kv expvar.KeyValue) {
		if t, ok := kv.Value.(T); ok {
			yield(kv.Key, t)
		}
	})
}

// MeshContext is an implementation of Context holding 'mesh'-related values.
//
type MeshContext struct {
	Context context.Context
	Namespace string

	Error error
}

func (m *MeshContext) Deadline() (deadline time.Time, ok bool) {
	return m.Context.Deadline()
}

func (m *MeshContext) Done() <-chan struct{} {
	return m.Context.Done()
}

func (m *MeshContext) Err() error {
	return m.Error
}

func (m *MeshContext) Value(key any) any {
	if keys, ok := key.(string); ok {
		namespace := m.Namespace
		if namespace == "" {
			namespace = "default"
		}
		mm := modMap(DefaultContext, defPrefix)
		v := mm.Get(keys)
		return v
	}
	return m.Context.Value(key)
}

func ContextValue[T any](ctx context.Context, key any) T {
	var res T
	v := ctx.Value(key)
	if vt, ok := v.(T); ok {
		return vt
	}
	return res
}


var DefaultContext context.Context = &MeshContext{Context: context.Background(), Namespace: "default"}

// RequestContext is a context associated with a request (HTTP, connection).
// This may be derived from a MeshContext, or wrap a context created by a framework.
//
//
type RequestContext struct {
	Context context.Context
	Start time.Time

	Error error

	// Slog
	Logger *slog.Logger

	// Client is the client identity - usually from a JWT or header.
	Client string

	// Peer is the peer identity - usually from mTLS client cert.
	Peer   string

}

func (a *RequestContext) Deadline() (deadline time.Time, ok bool) {
	return a.Context.Deadline()
}

func (a *RequestContext) Done() <-chan struct{} {
	return a.Context.Done()
}

func (a *RequestContext) Err() error {
	return a.Context.Err()
}

// Value may return the AuthContext, if chained - or one of the fields.
// Otherwise will pass to parent.
func (a *RequestContext) Value(key any) any {
	switch key {
	case "client": return a.Client
	}
	return a.Context.Value(key)
}

// ContextDialer is same with x.net.proxy.ContextDialer
// Used to create the actual connection to an address using the mesh.
// The result may have metadata, and be an instance of util.Stream.
//
// A uGate implements this interface, it is the primary interface
// for creating streams where the caller does not want to pass custom
// metadata. Based on net and addr and handshake, if destination is
// capable we will upgrade to BTS and pass metadata. This may also
// be sent via an egress gateway.
//
// For compatibility, 'net' can be "tcp" and addr a mangled hostname:port
// Mesh addresses can be identified by the hostname or IP6 address.
// External addresses will create direct connections if possible, or
// use egress server.
//
// TODO: also support 'url' scheme
type ContextDialer interface {
	// Dial with a context based on tls package - 'once successfully
	// connected, any expiration of the context will not affect the
	// connection'.
	DialContext(ctx context.Context, net, addr string) (net.Conn, error)
}

// HTTPDialer can produce configured http Clients for a destination - can be host:port or
// URL.
type HTTPDialer interface {
	HttpClient(ctx context.Context, dest string) *http.Client
}

// TokenSource is a common interface for anything returning Bearer or other kind of tokens.
type TokenSource interface {
	// GetToken for a given audience.
	GetToken(context.Context, string) (string, error)
}

// CertSource is a source of certificates.
type CertSource interface {
	// GetToken for a given audience.
	GetCertificate(ctx context.Context, sni string) (*tls.Certificate, error)
}

// UDPHandler is used to abstract the handling of incoming UDP packets on a UDP
// listener or TUN.
type UDPHandler interface {
	HandleUdp(dstAddr net.IP, dstPort uint16, localAddr net.IP, localPort uint16, data []byte)
}

// UdpWriter is the interface implemented by the TunTransport, to send
// packets back to the virtual interface. TUN or TProxy raw support this.
// Required for 'transparent' capture of UDP - otherwise use STUN/TURN/etc.
// A UDP NAT does not need this interface.
type UdpWriter interface {
	WriteTo(data []byte, dstAddr *net.UDPAddr, srcAddr *net.UDPAddr) (int, error)
}

// Unmarshaller abstracts the Unmarshal dependencies - like yaml and proto parsers.
type Unmarshaller interface {
	Unmarshal(data []byte, out any) error
}

// LabelGetter is an interface supported by resources that have labels (real or virtual)
type LabelGetter interface {
	Label(ctx context.Context, key string) string
}
