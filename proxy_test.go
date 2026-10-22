package retryabledns

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// stalledProxy starts a TCP listener that accepts connections and never
// answers, like a SOCKS5 proxy that hangs during the handshake. It returns the
// listener address.
func stalledProxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			_ = conn.Close()
		}
	})
	return ln.Addr().String()
}

// TestProxyDialHonorsTimeout ensures Timeout bounds the proxy handshake, so a
// stalled proxy can't block a query forever.
func TestProxyDialHonorsTimeout(t *testing.T) {
	const timeout = 500 * time.Millisecond
	client, err := NewWithOptions(Options{
		BaseResolvers: []string{"127.0.0.1:53"},
		MaxRetries:    1,
		Timeout:       timeout,
		Proxy:         "socks5://" + stalledProxy(t),
	})
	require.NoError(t, err)

	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(fakeHost), dns.TypeA)
	queries := map[string]func() error{
		"Do": func() error {
			_, err := client.Do(msg)
			return err
		},
		"QueryMultiple": func() error {
			_, err := client.QueryMultiple(fakeHost, []uint16{dns.TypeA})
			return err
		},
	}
	for name, query := range queries {
		t.Run(name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() { done <- query() }()
			select {
			case err := <-done:
				require.Error(t, err)
			case <-time.After(10 * timeout):
				t.Fatalf("query still blocked after %s with Timeout %s", 10*timeout, timeout)
			}
		})
	}
}

// socksProxy is a minimal SOCKS5 proxy for tests: no authentication, CONNECT
// only. It relays each connection to its target and remembers the local
// address of every upstream connection, so a test can tell whether a query
// reached a resolver through the proxy.
type socksProxy struct {
	addr     string
	mu       sync.Mutex
	upstream map[string]struct{}
}

func newSOCKSProxy(t *testing.T) *socksProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &socksProxy{addr: ln.Addr().String(), upstream: make(map[string]struct{})}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

func (p *socksProxy) URL() string { return "socks5://" + p.addr }

// relayed reports whether addr is the source of a connection the proxy opened.
func (p *socksProxy) relayed(addr net.Addr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.upstream[addr.String()]
	return addr.Network() == "tcp" && ok
}

func (p *socksProxy) serve(client net.Conn) {
	defer func() { _ = client.Close() }()
	target, err := socksHandshake(client)
	if err != nil {
		return
	}
	upstream, err := net.Dial("tcp", target)
	if err != nil {
		_, _ = client.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}) // connection refused
		return
	}
	defer func() { _ = upstream.Close() }()
	p.mu.Lock()
	p.upstream[upstream.LocalAddr().String()] = struct{}{}
	p.mu.Unlock()
	if _, err := client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	go func() {
		_, _ = io.Copy(upstream, client)
		_ = upstream.(*net.TCPConn).CloseWrite()
	}()
	_, _ = io.Copy(client, upstream)
}

// socksHandshake accepts a SOCKS5 greeting without authentication, reads the
// CONNECT request, and returns its target address.
func socksHandshake(conn net.Conn) (string, error) {
	buf := make([]byte, 256)
	// Greeting: VER NMETHODS METHODS.
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", err
	}
	if _, err := io.ReadFull(conn, buf[:buf[1]]); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return "", err
	}
	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT.
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return "", err
	}
	atyp := buf[3]
	var addrLen int
	switch atyp {
	case 1:
		addrLen = net.IPv4len
	case 4:
		addrLen = net.IPv6len
	case 3:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return "", err
		}
		addrLen = int(buf[0])
	default:
		return "", fmt.Errorf("unsupported address type %d", atyp)
	}
	if _, err := io.ReadFull(conn, buf[:addrLen+2]); err != nil {
		return "", err
	}
	host := string(buf[:addrLen])
	if atyp != 3 {
		host = net.IP(buf[:addrLen]).String()
	}
	port := binary.BigEndian.Uint16(buf[addrLen : addrLen+2])
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// requireProxied fails unless fr received queries and every one of them
// arrived over a connection the proxy relayed.
func requireProxied(t *testing.T, p *socksProxy, fr *fakeResolver) {
	t.Helper()
	remotes := fr.Remotes()
	require.NotEmpty(t, remotes, "resolver received no queries")
	for _, addr := range remotes {
		require.True(t, p.relayed(addr), "query from %s %s bypassed the proxy", addr.Network(), addr)
	}
}

// TestUDPResolversUseProxy ensures UDP resolvers go through the proxy over
// TCP, whether they come from BaseResolvers or are passed per call, and even
// when a pool exists for their address.
func TestUDPResolversUseProxy(t *testing.T) {
	for _, threads := range []int{0, 2} {
		t.Run(fmt.Sprintf("ConnectionPoolThreads=%d", threads), func(t *testing.T) {
			fr := newFakeResolverDual(t, dns.RcodeSuccess, arecord(fakeHost, "203.0.113.10"))
			socks := newSOCKSProxy(t)
			client, err := NewWithOptions(Options{
				BaseResolvers:         []string{fr.Addr()},
				MaxRetries:            1,
				Timeout:               time.Second,
				ConnectionPoolThreads: threads,
				Proxy:                 socks.URL(),
			})
			require.NoError(t, err)
			t.Cleanup(client.Close)

			d, err := client.QueryMultipleWithResolver(fakeHost, []uint16{dns.TypeA}, networkResolver(t, UDP, fr.Addr()))
			require.NoError(t, err)
			require.Equal(t, []string{"203.0.113.10"}, d.A)

			d, err = client.QueryMultiple(fakeHost, []uint16{dns.TypeA})
			require.NoError(t, err)
			require.Equal(t, []string{"203.0.113.10"}, d.A)

			msg := &dns.Msg{}
			msg.SetQuestion(dns.Fqdn(fakeHost), dns.TypeA)
			_, err = client.Do(msg)
			require.NoError(t, err)

			requireProxied(t, socks, fr)
			require.EqualValues(t, 3, fr.Queries())
		})
	}
}
