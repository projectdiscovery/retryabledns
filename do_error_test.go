package retryabledns

import (
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// closedTCPAddr returns a 127.0.0.1 address that nothing listens on, so
// dialing it fails with connection refused.
func closedTCPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

func TestDo_RetriesExceededKeepsLastError(t *testing.T) {
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	t.Run("proxy refusing connections", func(t *testing.T) {
		client, err := NewWithOptions(Options{
			BaseResolvers: []string{"127.0.0.1:53"},
			Proxy:         "socks5://" + closedTCPAddr(t),
			MaxRetries:    2,
			Timeout:       time.Second,
		})
		require.NoError(t, err)

		_, err = client.Do(msg)
		require.ErrorIs(t, err, ErrRetriesExceeded)
		require.ErrorIs(t, err, syscall.ECONNREFUSED,
			"Do must expose the last attempt's error, not only ErrRetriesExceeded")
		var opErr *net.OpError
		require.ErrorAs(t, err, &opErr)
	})

	t.Run("no underlying error", func(t *testing.T) {
		nx := newFakeResolver(t, dns.RcodeNameError)
		client := newLegacyClient(t, nx.Addr())

		resp, err := client.Do(msg)
		require.Equal(t, ErrRetriesExceeded, err,
			"without an underlying error Do must return the bare sentinel")
		require.NotNil(t, resp)
		require.Equal(t, dns.RcodeNameError, resp.Rcode)
	})
}
