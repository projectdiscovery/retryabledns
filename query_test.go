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

// TestQueryMultipleAXFRWithDoH ensures a zone transfer through a DoH resolver
// returns the resolver's reply instead of blocking on a transfer stream that
// never ran, and that a failed transfer attempt doesn't hide the reply of the
// next one.
func TestQueryMultipleAXFRWithDoH(t *testing.T) {
	doh := newFakeDoHResolver(t, dns.RcodeSuccess, arecord(fakeHost, "203.0.113.10"))
	refusing := newFakeResolverTCP(t, dns.RcodeRefused)

	tests := map[string]struct {
		baseResolvers []string
		maxRetries    int
		query         func(*Client) (*DNSData, error)
		transfers     int64 // zone transfers the refusing resolver receives
	}{
		"QueryMultiple": {
			baseResolvers: []string{doh.ResolverString("post")},
			maxRetries:    1,
			query: func(c *Client) (*DNSData, error) {
				return c.QueryMultiple(fakeHost, []uint16{dns.TypeAXFR})
			},
		},
		"QueryMultipleWithResolver": {
			baseResolvers: []string{doh.ResolverString("post")},
			maxRetries:    1,
			query: func(c *Client) (*DNSData, error) {
				return c.QueryMultipleWithResolver(fakeHost, []uint16{dns.TypeAXFR}, parseResolver(doh.ResolverString("get")))
			},
		},
		// The client advances its resolver index before each attempt, starting
		// from 0, so the first attempt goes to the second resolver (the
		// refusing transfer) and the second attempt to DoH.
		"after a failed transfer": {
			baseResolvers: []string{doh.ResolverString("post"), "tcp:" + refusing.Addr()},
			maxRetries:    2,
			query: func(c *Client) (*DNSData, error) {
				return c.QueryMultiple(fakeHost, []uint16{dns.TypeAXFR})
			},
			transfers: 1,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			transfers := refusing.Queries()
			client, err := NewWithOptions(Options{
				BaseResolvers: tt.baseResolvers,
				MaxRetries:    tt.maxRetries,
				Timeout:       time.Second,
			})
			require.NoError(t, err)
			t.Cleanup(client.Close)

			type result struct {
				data *DNSData
				err  error
			}
			done := make(chan result, 1)
			go func() {
				d, err := tt.query(client)
				done <- result{d, err}
			}()

			select {
			case res := <-done:
				require.NoError(t, res.err)
				require.Equal(t, []string{"203.0.113.10"}, res.data.A)
			case <-time.After(5 * time.Second):
				t.Fatal("zone transfer through DoH still blocked after 5s")
			}
			require.EqualValues(t, tt.transfers, refusing.Queries()-transfers, "zone transfers sent to the refusing resolver")
		})
	}
}
