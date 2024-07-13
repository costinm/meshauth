package meshauth

import (
	"context"
	"net"
)

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



