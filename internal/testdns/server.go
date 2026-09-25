// Package testdns runs a real, controllable DNS server on the loopback
// interface so that plugin and upstream behaviour can be exercised over actual
// UDP and TCP sockets instead of a stand-in.
//
// One server answers on a single port over both transports. The handler sees
// the transport a query arrived on, may answer with a truncated message to
// exercise the UDP to TCP retry, and every received query is recorded so a test
// can assert which server was asked, over which protocol, and how often.
package testdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/miekg/dns"
)

// Protocol names the transport a query arrived on. It is passed to a Handler
// through Protocol and recorded on every recorded Query.
const (
	ProtocolUDP = "udp"
	ProtocolTCP = "tcp"
)

// Handler answers one received query. Returning nil answers with SERVFAIL, so a
// handler that wants to drop a query cannot make a client wait forever.
// Returning a message with Truncated set answers a UDP query with a truncated
// message; the handler is expected to return the complete answer to the TCP
// retry that follows.
type Handler func(context.Context, *dns.Msg) *dns.Msg

// Query is one received query. QName and QType are empty when the query carried
// no question.
type Query struct {
	Protocol string
	ID       uint16
	QName    string
	QType    uint16
	QClass   uint16
}

// Server is a running UDP and TCP DNS server. It is safe for concurrent use.
type Server struct {
	address string
	handler Handler

	udp *dns.Server
	tcp *dns.Server

	mu        sync.Mutex
	queries   []Query
	connOpen  int
	connClose int

	closeOnce sync.Once
	closeErr  error
}

type protocolContextKey struct{}

// Protocol reports the transport the handled query arrived on, as ProtocolUDP or
// ProtocolTCP. It returns an empty string for a context that did not come from
// this package.
func Protocol(ctx context.Context) string {
	protocol, _ := ctx.Value(protocolContextKey{}).(string)
	return protocol
}

// Start runs a server on an ephemeral 127.0.0.1 port.
func Start(handler Handler) (*Server, error) {
	return StartOn("127.0.0.1:0", handler)
}

// StartOn runs a server on the given address. Pass a concrete port to place
// several servers on one port but different loopback addresses, which is how a
// test gives one generation several distinct upstreams.
func StartOn(address string, handler Handler) (*Server, error) {
	if handler == nil {
		return nil, errors.New("testdns: handler must not be nil")
	}

	packetConn, listener, err := listen(address)
	if err != nil {
		return nil, err
	}

	server := &Server{address: listener.Addr().String(), handler: handler}
	server.udp = &dns.Server{
		PacketConn: packetConn,
		Handler:    dns.HandlerFunc(server.serve(ProtocolUDP)),
	}
	server.tcp = &dns.Server{
		Listener: &trackedListener{Listener: listener, server: server},
		Handler:  dns.HandlerFunc(server.serve(ProtocolTCP)),
	}

	// A server that has not started yet would answer nothing, so wait for both
	// read loops to be serving before handing the address to a test.
	started := make(chan struct{}, 2)
	stopped := make(chan error, 2)
	server.udp.NotifyStartedFunc = func() { started <- struct{}{} }
	server.tcp.NotifyStartedFunc = func() { started <- struct{}{} }
	go func() { stopped <- server.udp.ActivateAndServe() }()
	go func() { stopped <- server.tcp.ActivateAndServe() }()
	for range 2 {
		select {
		case <-started:
		case err := <-stopped:
			_ = packetConn.Close()
			_ = listener.Close()
			return nil, fmt.Errorf("testdns: a transport stopped before it served: %w", err)
		}
	}
	return server, nil
}

// portAttempts is how often a free port is chosen again when the TCP socket
// beside it cannot be bound.
const portAttempts = 8

// listen binds both transports on one port. The UDP socket is bound first
// because a zero port asks the kernel to pick one, and the TCP socket then
// reuses that port. A port that is free for UDP can still be taken for TCP by a
// socket that is closing, so a zero port is chosen again when the pair fails.
func listen(address string) (net.PacketConn, net.Listener, error) {
	if _, port, err := net.SplitHostPort(address); err != nil {
		return nil, nil, fmt.Errorf("testdns: invalid listen address %q: %w", address, err)
	} else if port != "0" {
		return listenPair(address)
	}

	var failure error
	for range portAttempts {
		packetConn, listener, err := listenPair(address)
		if err == nil {
			return packetConn, listener, nil
		}
		failure = err
	}
	return nil, nil, failure
}

// listenPair binds one UDP port and the TCP port beside it.
func listenPair(address string) (net.PacketConn, net.Listener, error) {
	packetConn, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, nil, fmt.Errorf("testdns: listen udp %s: %w", address, err)
	}
	bound := packetConn.LocalAddr().String()
	listener, err := net.Listen("tcp", bound)
	if err != nil {
		_ = packetConn.Close()
		return nil, nil, fmt.Errorf("testdns: listen tcp %s: %w", bound, err)
	}
	return packetConn, listener, nil
}

// Address is the "host:port" both transports answer on.
func (s *Server) Address() string {
	return s.address
}

// Close stops both transports. It is safe to call more than once.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = errors.Join(s.udp.Shutdown(), s.tcp.Shutdown())
	})
	return s.closeErr
}

// Queries returns a snapshot of every query received so far, in arrival order.
func (s *Server) Queries() []Query {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Query(nil), s.queries...)
}

// Count reports how many received queries match the given protocol and, when
// name is not empty, that question name. Names are compared as received.
func (s *Server) Count(protocol, name string) int {
	count := 0
	for _, query := range s.Queries() {
		if protocol != "" && query.Protocol != protocol {
			continue
		}
		if name != "" && query.QName != name {
			continue
		}
		count++
	}
	return count
}

// TCPConns reports how many TCP connections this server has accepted and how
// many of them have been torn down. A client that closes its upstream releases
// the connection, which is how a test observes that a client was closed.
func (s *Server) TCPConns() (opened, closed int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connOpen, s.connClose
}

func (s *Server) serve(protocol string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, request *dns.Msg) {
		s.record(protocol, request)

		ctx := context.WithValue(context.Background(), protocolContextKey{}, protocol)
		response := s.handler(ctx, request)
		if response == nil {
			response = new(dns.Msg)
			response.SetRcode(request, dns.RcodeServerFailure)
		}
		if err := w.WriteMsg(response); err != nil {
			// The querier is gone or the socket failed; there is no way to
			// report it, and the recorded query already tells the story.
			_ = err
		}
	}
}

func (s *Server) record(protocol string, request *dns.Msg) {
	query := Query{Protocol: protocol, ID: request.Id}
	if len(request.Question) > 0 {
		query.QName = request.Question[0].Name
		query.QType = request.Question[0].Qtype
		query.QClass = request.Question[0].Qclass
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = append(s.queries, query)
}

func (s *Server) acceptConn() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connOpen++
}

func (s *Server) closeConn() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connClose++
}

// trackedListener counts the TCP connections this server accepts and the
// connections that have ended.
type trackedListener struct {
	net.Listener
	server *Server
}

func (l *trackedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.server.acceptConn()
	return &trackedConn{Conn: conn, server: l.server}, nil
}

type trackedConn struct {
	net.Conn
	server *Server
	once   sync.Once
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.server.closeConn)
	return err
}
