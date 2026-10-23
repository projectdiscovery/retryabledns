package retryabledns

import (
	"net"
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
