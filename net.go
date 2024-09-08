package meshauth

import (
	"context"
	"errors"
	"net"
	"net/http"
)



type Router struct {
	Name string

	Paths map[string]string

	Mux *http.ServeMux
}

// DialContext should connect to the address, using one of the modules
// and config - falling back to the default dialer.
//
// Normal golang - network is "tcp" and address is host:port - or custom values are allowed.
//
// All forwarding/tunneling methods should call this method to establish
// outbound connections.
func (mesh *Mesh) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {

	c := mesh.GetDest(addr)
	if c == nil {
		host, _, _ := net.SplitHostPort(addr)
		c = mesh.GetDest(host)
	}

	if c != nil {
		if c.Dialer == nil && c.Proto != "" {
			// TODO: set proto based on labels
			c.Dialer = mesh.MuxDialers[c.Proto]
		}

		if c.Dialer != nil {
			return c.Dialer.DialContext(ctx, network, addr)
		} else {
			return nil, errors.New("Missing dialer for protocol " + c.Proto + " for " + addr)
		}

		// TODO: routing, etc - based on endpoints and TcpRoutes
	}

	// TODO: if egress gateway is set, use it ( redirect all unknown to egress )
	// TODO: CIDR range of Endpoints, Nodes, VIPs to use hbone
	// TODO: if port, use SNI or match clusters
	nc, err := mesh.NetDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	// If net connection is cut, by default the socket may linger for up to 20 min without detecting this.
	// Extracted from gRPC - needs to apply at TCP socket level
	//if c.TCPUserTimeout != 0 {
	//	syscall.SetTCPUserTimeout(nc, c.TCPUserTimeout)
	//}

	return nc, err
}

//
//// HandleUdp is the common entry point for UDP capture.
//// - tproxy
//// - gvisor/lwIP
//// WIP
//func (ug *Mesh) HandleUdp(dstAddr net.IP, dstPort uint16,
//		localAddr net.IP, localPort uint16,
//		data []byte) {
//	log.Println("TProxy UDP ", dstAddr, dstPort, localAddr, localPort, len(data))
//}

