package xnet

import (
	"context"
	"io"
	"net"
)

// Interfaces for proxying network connections.

type ProxyDialer interface {
	ProxyDial(ctx context.Context, dest string, c net.Conn) (ProxyConn, error)
}

type ProxyConn interface {
	ProxyTo(ch io.ReadWriteCloser) error
}
