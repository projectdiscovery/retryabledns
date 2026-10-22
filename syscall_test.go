package retryabledns

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// TestResolveWithSyscallIgnoresClientOptions pins the behavior that the
// ResolveWithSyscall doc comment describes: the lookup goes through the
// operating system's resolver, so neither BaseResolvers nor Proxy is used.
func TestResolveWithSyscallIgnoresClientOptions(t *testing.T) {
	// A resolver that would answer "localhost" with a distinctive address
	// if the client ever queried it.
	resolver := newFakeResolver(t, dns.RcodeSuccess, arecord("localhost.", "203.0.113.7"))

	// A listener standing in for the SOCKS5 proxy. It only counts accepted
	// connections.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	var accepted atomic.Int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()

	client, err := NewWithOptions(Options{
		BaseResolvers: []string{resolver.Addr()},
		Proxy:         "socks5://" + ln.Addr().String(),
		MaxRetries:    1,
		Timeout:       time.Second,
	})
	require.NoError(t, err)

	data, err := client.ResolveWithSyscall("localhost")
	require.NoError(t, err)
	require.Equal(t, "localhost", data.Host)

	// The OS resolver returns the loopback address from the hosts file,
	// not the address served by the fake resolver.
	addrs := append(append([]string{}, data.A...), data.AAAA...)
	require.NotEmpty(t, addrs)
	for _, addr := range addrs {
		require.True(t, net.ParseIP(addr).IsLoopback(), "want loopback address, got %s", addr)
	}
	require.NotContains(t, data.A, "203.0.113.7")

	require.Zero(t, resolver.Queries(), "BaseResolvers must not be queried")
	require.Zero(t, accepted.Load(), "Proxy must not be dialed")
}
