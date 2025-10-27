package meshauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"
)

/*
The mesh is lazy - which is the most scalable design, trading off latency
on the first request for a given peer with 'internet scale', low startup
cost, low config size.

This is very different from Istio v1 - where ALL config for the mesh is sent
 to ALL nodes, trading huge config and high startup cost for ~100 ms for
each initial connection.

Browsers and most internet apps are lazy too - they don't know about a peer
DNS and other properties until they are needed.

On the listener side, mesh capturing egress can also be lazy - SOCKS or captured outbond connections can be configured on-demand, and same for
accepted inbound connections.

The mesh still need to listens on a couple of ports:
- inbound tproxy capture
- egress tproxy capture
- SOCKS for non-capture egress
- HTTP/2 H2C for 'sandwitched' mesh with L4 secure
- H2 and SSH for native security.
- http for local admin and control

The mesh model is also 'peer to peer' - each node can request or serve
'resources' or streams, and may use established peering (SSH for example,
or already estabilished trust and metadata, address).

*/

// Module abstract a Listener and a component capable of handling accepted
// connections (and UDP equivalent).
//
// The low level net.Listener needs to be abstracted - the accepted streams
// may be forwarded, encrypted, etc.
type Module struct {
	Address string `json:"address,omitempty"`

	// Modules that listen to a port should use this listener or implement a
	// Handle or HandleConn method.
	NetListener net.Listener `json:"-"`

	// TODO: rename to 'remoteAddress' or 'dest' - use to indicate an address to use as client
	ForwardTo string `json:"forwardTo,omitempty"`

	// Provides access to the config, DialContext, RoundTripper, tokens and certs
	Mesh *Mesh `json:"-"`

	// Handler for the accepted connections.
	Handler string `json:"handler,omitempty"`

	// The module native interface.
	Module any `json:"-"`

	// TODO: keep alive options, etc

	closed   chan struct{}
	incoming chan net.Conn
	netAddr  net.Addr

	initf       func(m *Module) error
	ConnHandler func(net.Conn) `json:"-"`
}

var NewListener func(ctx context.Context, addr string) net.Listener

func (m *Module) String() string {
	b, _ := json.Marshal(m)
	return string(b)
}

func (m *Module) Provision(ctx context.Context) error {
	var err error
	m.incoming = make(chan net.Conn)
	m.closed = make(chan struct{})

	if m.Address != "" {
		if m.NetListener == nil {
			if NewListener != nil {
				m.NetListener = NewListener(context.Background(), m.Address)
				// May be nil or a virtual listener (reverse)
			} else {
				m.NetListener, err = Listen(m.Address)
			}
		}
	}
	if m.initf != nil {
		err = m.initf(m)
		if err != nil {
			return err
		}
	}
	return err
}

func (m *Module) Start() error {
	var err error

	if m.NetListener != nil {
		go m.serve()
	}

	return err
}

func Listen(addr string) (net.Listener, error) {
	if os.Getenv("NO_FIXED_PORTS") != "" {
		addr = ":0"
	}
	if strings.HasPrefix(addr, "/") ||
		strings.HasPrefix(addr, "@") {
		if strings.HasPrefix(addr, "/") {
			if _, err := os.Stat(addr); err == nil {
				os.Remove(addr)
			}
		}
		us, err := net.ListenUnix("unix",
			&net.UnixAddr{
				Name: addr,
				Net:  "unix",
			})
		if err != nil {
			return nil, err
		}

		return us, err
	}

	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return listener, err
}

func ListenAndServe(addr string, f func(conn net.Conn)) (net.Listener, error) {
	m := &Module{
		Address:     addr,
		ConnHandler: f,
	}
	err := m.Provision(context.Background())
	if err != nil {
		return nil, err
	}
	err = m.Start()
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Module) serve() {
	if m.ConnHandler != nil {
		serveListener(m.NetListener, m.ConnHandler)
		return
	}
	if hl, ok := m.Module.(interface{ HandleConn(net.Conn) error }); ok {
		serveListener(m.NetListener, func(conn net.Conn) {
			hl.HandleConn(conn)
		})
		return
	}
	// TODO: add a context - including the FS, Mesh and raw conn
	if hl, ok := m.Module.(interface {
		HandleStream(writer io.Writer, r io.Reader) error
	}); ok {
		serveListener(m.NetListener, func(conn net.Conn) {
			hl.HandleStream(conn, conn)
		})
		return
	}
}

func serveListener(l net.Listener, f func(conn net.Conn)) {
	for {
		remoteConn, err := l.Accept()
		if err != nil {
			if ne, ok := err.(interface{ Temporary() bool }); ok && ne.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			// TODO: callback to notify. This may happen if interface restarts, etc.
			slog.Warn("ListenerDone", "addr", l.Addr())
			return
		}

		// TODO: set read/write deadlines

		go f(remoteConn)
	}
}

func (l *Module) OnConnection(c net.Conn) error {
	l.incoming <- c
	return nil
}

func (l *Module) Close() error {
	l.closed <- struct{}{}
	return nil
}

func (l *Module) Addr() net.Addr {
	if l.netAddr != nil {
		return l.netAddr
	}
	if l.NetListener != nil {
		return l.NetListener.Addr()
	}
	return l.netAddr
}

func (l *Module) Accept() (net.Conn, error) {
	if l.NetListener != nil {
		return l.NetListener.Accept()
	}
	for {
		select {
		case c, ok := <-l.incoming:
			if !ok {
				return nil, fmt.Errorf("listener is closed")
			}
			return c, nil
		case <-l.closed:
			return nil, fmt.Errorf("listener is closed")
		}
	}
}
