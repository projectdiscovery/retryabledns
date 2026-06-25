package retryabledns

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"
)

// countingDialer is a proxy.Dialer that hands out fake connections while
// tracking how many are open simultaneously. It lets the proxy retry paths be
// exercised without a real SOCKS server.
type countingDialer struct {
	mu         sync.Mutex
	live       int
	total      int
	maxConcurr int
}

func (d *countingDialer) Dial(network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.live++
	d.total++
	if d.live > d.maxConcurr {
		d.maxConcurr = d.live
	}
	d.mu.Unlock()
	return &fakeConn{d: d}, nil
}

func (d *countingDialer) snapshot() (live, total, maxConcurr int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.live, d.total, d.maxConcurr
}

// fakeConn satisfies net.Conn. Reads fail immediately so each DNS exchange
// errors quickly and the client retries; Close decrements the live counter and
// is safe to call more than once.
type fakeConn struct {
	d      *countingDialer
	closed bool
}

func (c *fakeConn) Read(b []byte) (int, error)  { return 0, io.ErrUnexpectedEOF }
func (c *fakeConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *fakeConn) Close() error {
	c.d.mu.Lock()
	defer c.d.mu.Unlock()
	if !c.closed {
		c.closed = true
		c.d.live--
	}
	return nil
}
func (c *fakeConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func newProxyTestClient(t *testing.T, d proxy.Dialer, maxRetries int) *Client {
	t.Helper()
	client, err := NewWithOptions(Options{
		BaseResolvers: []string{"tcp:127.0.0.1:53"},
		MaxRetries:    maxRetries,
		Timeout:       time.Second,
	})
	require.NoError(t, err)
	// inject the proxy dialer so the proxied TCP paths are taken
	client.tcpProxy = d
	client.resolvers = []Resolver{&NetworkResolver{Protocol: TCP, Host: "127.0.0.1", Port: "53"}}
	return client
}

// TestDoProxyNoConnLeak ensures Do closes each proxied connection before the
// next retry instead of deferring every Close to function return (which leaked
// one socket per retry).
func TestDoProxyNoConnLeak(t *testing.T) {
	const maxRetries = 5
	d := &countingDialer{}
	client := newProxyTestClient(t, d, maxRetries)

	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	_, _ = client.Do(msg)

	live, total, maxConcurr := d.snapshot()
	require.Equal(t, 0, live, "every proxied connection must be closed")
	require.Equal(t, maxRetries, total, "each retry should dial exactly once")
	require.LessOrEqual(t, maxConcurr, 1, "at most one proxied connection may be open at a time")
}

// TestQueryMultipleProxyNoConnLeak ensures the enriched query path also caps
// concurrent proxied connections at one across retries and request types.
func TestQueryMultipleProxyNoConnLeak(t *testing.T) {
	const maxRetries = 4
	d := &countingDialer{}
	client := newProxyTestClient(t, d, maxRetries)

	_, _ = client.QueryMultiple("example.com", []uint16{dns.TypeA, dns.TypeAAAA})

	live, total, maxConcurr := d.snapshot()
	require.Equal(t, 0, live, "every proxied connection must be closed")
	// The first request type exhausts its retries and the outer loop bails with
	// ErrRetriesExceeded, so exactly maxRetries dials occur; the key invariant is
	// that they never pile up.
	require.Equal(t, maxRetries, total, "each retry should dial exactly once")
	require.LessOrEqual(t, maxConcurr, 1, "at most one proxied connection may be open at a time")
}
