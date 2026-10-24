package retryabledns

import (
	"crypto/tls"
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
// TCP, whether they come from BaseResolvers or are passed per call, and
// whether or not ConnectionPoolThreads asks for pools.
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

// TestDoTUsesProxy ensures DoT queries go through the proxy.
func TestDoTUsesProxy(t *testing.T) {
	fr, roots := newFakeDoTResolver(t, dns.RcodeSuccess, arecord(fakeHost, "203.0.113.10"))
	socks := newSOCKSProxy(t)
	client, err := NewWithOptions(Options{
		BaseResolvers: []string{"dot:" + fr.Addr()},
		MaxRetries:    1,
		Timeout:       time.Second,
		Proxy:         socks.URL(),
	})
	require.NoError(t, err)
	client.dotClient.TLSConfig = &tls.Config{RootCAs: roots}

	d, err := client.QueryMultiple(fakeHost, []uint16{dns.TypeA})
	require.NoError(t, err)
	require.Equal(t, []string{"203.0.113.10"}, d.A)

	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(fakeHost), dns.TypeA)
	_, err = client.Do(msg)
	require.NoError(t, err)

	requireProxied(t, socks, fr)
	require.EqualValues(t, 2, fr.Queries())
}

// TestDoTHandshakeHonorsTimeout ensures Timeout bounds the TLS handshake on a
// proxied DoT connection, so a resolver that never answers can't block a query.
func TestDoTHandshakeHonorsTimeout(t *testing.T) {
	const timeout = 500 * time.Millisecond
	client, err := NewWithOptions(Options{
		// stalledProxy also stands in for a DoT resolver that accepts the
		// connection but never answers the TLS handshake.
		BaseResolvers: []string{"dot:" + stalledProxy(t)},
		MaxRetries:    1,
		Timeout:       timeout,
		Proxy:         newSOCKSProxy(t).URL(),
	})
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		_, err := client.QueryMultiple(fakeHost, []uint16{dns.TypeA})
		done <- err
	}()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(10 * timeout):
		t.Fatalf("query still blocked after %s with Timeout %s", 10*timeout, timeout)
	}
}

// TestAXFRUsesProxy ensures zone transfers go through the proxy, like the NS
// and A lookups that precede them.
func TestAXFRUsesProxy(t *testing.T) {
	fr := newFakeAXFRResolver(t, []dns.RR{
		soarecord("zonetransfer.test"),
		arecord("host.zonetransfer.test", "203.0.113.2"),
		soarecord("zonetransfer.test"),
	})
	socks := newSOCKSProxy(t)
	client, err := NewWithOptions(Options{
		BaseResolvers: []string{fr.Addr()},
		MaxRetries:    1,
		Timeout:       time.Second,
		Proxy:         socks.URL(),
	})
	require.NoError(t, err)

	axfrData, err := client.AXFR("zonetransfer.test")
	require.NoError(t, err)
	require.Len(t, axfrData.DNSData, 1)
	require.Equal(t, []string{"203.0.113.2"}, axfrData.DNSData[0].A)
	requireProxied(t, socks, fr)
}

// TestTCPFallback ensures a truncated reply is retried over TCP, through the
// proxy when one is set.
func TestTCPFallback(t *testing.T) {
	truncated := func(req *dns.Msg) *dns.Msg {
		m := fixedResponse(dns.RcodeSuccess, []dns.RR{arecord(fakeHost, "203.0.113.10")})(req)
		m.Truncated = true
		return m
	}

	t.Run("direct", func(t *testing.T) {
		fr := &fakeResolver{respond: truncated}
		fr.startUDP(t, "127.0.0.1:0")
		fr.startTCP(t, fr.addr)
		client, err := NewWithOptions(Options{
			BaseResolvers: []string{fr.Addr()},
			MaxRetries:    1,
			Timeout:       time.Second,
		})
		require.NoError(t, err)
		client.TCPFallback = true

		d, err := client.QueryMultiple(fakeHost, []uint16{dns.TypeA})
		require.NoError(t, err)
		require.Equal(t, []string{"203.0.113.10"}, d.A)
		remotes := fr.Remotes()
		require.Len(t, remotes, 2)
		require.Equal(t, "udp", remotes[0].Network())
		require.Equal(t, "tcp", remotes[1].Network(), "a truncated reply must be retried over TCP")
	})

	t.Run("proxy", func(t *testing.T) {
		fr := &fakeResolver{respond: truncated}
		fr.startTCP(t, "127.0.0.1:0")
		socks := newSOCKSProxy(t)
		client, err := NewWithOptions(Options{
			BaseResolvers: []string{"tcp:" + fr.Addr()},
			MaxRetries:    1,
			Timeout:       time.Second,
			Proxy:         socks.URL(),
		})
		require.NoError(t, err)
		client.TCPFallback = true

		d, err := client.QueryMultiple(fakeHost, []uint16{dns.TypeA})
		require.NoError(t, err)
		require.Equal(t, []string{"203.0.113.10"}, d.A)
		require.EqualValues(t, 2, fr.Queries(), "a truncated reply must be retried once")
		requireProxied(t, socks, fr)
	})
}

// TestQueryParallelUsesProxy ensures QueryParallel sends its queries through
// the proxy.
func TestQueryParallelUsesProxy(t *testing.T) {
	fr := newFakeResolverDual(t, dns.RcodeSuccess, arecord(fakeHost, "203.0.113.10"))
	socks := newSOCKSProxy(t)
	client, err := NewWithOptions(Options{
		BaseResolvers: []string{"127.0.0.1:53"},
		MaxRetries:    1,
		Timeout:       time.Second,
		Proxy:         socks.URL(),
	})
	require.NoError(t, err)

	dnsdatas, err := client.QueryParallel(fakeHost, dns.TypeA, []string{fr.Addr()})
	require.NoError(t, err)
	require.Len(t, dnsdatas, 1)
	require.Equal(t, []string{"203.0.113.10"}, dnsdatas[0].A)
	requireProxied(t, socks, fr)
}

// TestTraceUsesProxy ensures Trace queries the root servers and resolves name
// server addresses through the proxy.
func TestTraceUsesProxy(t *testing.T) {
	const nsName = "ns1.trace.test."
	fr := &fakeResolver{respond: func(req *dns.Msg) *dns.Msg {
		m := &dns.Msg{}
		m.SetReply(req)
		if req.Question[0].Name == nsName {
			m.Answer = []dns.RR{arecord(nsName, "127.0.0.1")}
			return m
		}
		// A referral: no answer, and the name server in the authority section.
		m.Ns = []dns.RR{&dns.NS{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
			Ns:  nsName,
		}}
		return m
	}}
	fr.startUDP(t, "127.0.0.1:0")
	fr.startTCP(t, fr.addr)
	roots := RootDNSServersIPv4
	RootDNSServersIPv4 = []string{fr.Addr()}
	t.Cleanup(func() { RootDNSServersIPv4 = roots })

	socks := newSOCKSProxy(t)
	client, err := NewWithOptions(Options{
		BaseResolvers: []string{fr.Addr()},
		MaxRetries:    1,
		Timeout:       time.Second,
		Proxy:         socks.URL(),
	})
	require.NoError(t, err)

	// A max recursion of 2 runs one step: query the root, then resolve the
	// name server it returned.
	_, err = client.Trace(fakeHost, dns.TypeA, 2)
	require.NoError(t, err)
	require.EqualValues(t, 2, fr.Queries(), "root query plus the name server lookup")
	requireProxied(t, socks, fr)
}

// TestNoPoolsWithProxy ensures NewWithOptions opens no direct connections when
// Proxy is set: UDP pools would dial each resolver, resolving its hostname,
// outside the proxy, and queries never use them.
func TestNoPoolsWithProxy(t *testing.T) {
	client, err := NewWithOptions(Options{
		// .invalid never resolves (RFC 6761), so a direct lookup fails.
		BaseResolvers:         []string{"resolver.invalid:53"},
		MaxRetries:            1,
		ConnectionPoolThreads: 2,
		Proxy:                 newSOCKSProxy(t).URL(),
	})
	require.NoError(t, err)
	t.Cleanup(client.Close)
	require.Empty(t, client.udpConnPool.Map)
}
