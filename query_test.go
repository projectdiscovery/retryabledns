package retryabledns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func networkResolver(t *testing.T, protocol Protocol, addr string) *NetworkResolver {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	return &NetworkResolver{Protocol: protocol, Host: host, Port: port}
}

// TestQueryMultipleWithResolverUnpooledUDP ensures a UDP resolver passed per
// call is queried even though pools exist only for BaseResolvers.
func TestQueryMultipleWithResolverUnpooledUDP(t *testing.T) {
	pooled := newFakeResolver(t, dns.RcodeSuccess, arecord(fakeHost, "203.0.113.10"))
	unpooled := newFakeResolver(t, dns.RcodeSuccess, arecord(fakeHost, "203.0.113.20"))
	client, err := NewWithOptions(Options{
		BaseResolvers:         []string{pooled.Addr()},
		MaxRetries:            2,
		Timeout:               time.Second,
		ConnectionPoolThreads: 2,
	})
	require.NoError(t, err)
	t.Cleanup(client.Close)

	d, err := client.QueryMultiple(fakeHost, []uint16{dns.TypeA})
	require.NoError(t, err)
	require.Equal(t, []string{"203.0.113.10"}, d.A, "base resolver must answer through its pool")

	d, err = client.QueryMultipleWithResolver(fakeHost, []uint16{dns.TypeA}, networkResolver(t, UDP, unpooled.Addr()))
	require.NoError(t, err)
	require.Equal(t, []string{"203.0.113.20"}, d.A, "resolver without a pool must still be queried")
	require.EqualValues(t, 1, unpooled.Queries())
	require.EqualValues(t, 1, pooled.Queries())
}

type stubResolver struct{}

func (stubResolver) String() string { return "stub" }

// TestQueryMultipleWithResolverUnsupported ensures a resolver the client can't
// query produces an error instead of empty data and a nil error.
func TestQueryMultipleWithResolverUnsupported(t *testing.T) {
	fr := newFakeResolver(t, dns.RcodeSuccess, arecord(fakeHost, "203.0.113.10"))
	client, err := New([]string{fr.Addr()}, 2)
	require.NoError(t, err)

	resolvers := map[string]Resolver{
		"resolver type": stubResolver{},
		"protocol":      networkResolver(t, Protocol("quic"), fr.Addr()),
	}
	for name, resolver := range resolvers {
		t.Run(name, func(t *testing.T) {
			_, err := client.QueryMultipleWithResolver(fakeHost, []uint16{dns.TypeA}, resolver)
			require.ErrorIs(t, err, ErrRetriesExceeded)
		})
	}
	require.Zero(t, fr.Queries())
}
