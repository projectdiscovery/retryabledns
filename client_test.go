package retryabledns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestConsistentResolve(t *testing.T) {
	client := New([]string{"8.8.8.8:53", "1.1.1.1:53"}, 5)

	var last string
	for i := 0; i < 10; i++ {
		d, err := client.Resolve("example.com")
		require.Nil(t, err, "could not resolve dns")

		if last != "" {
			require.Equal(t, last, d.A[0], "got another data from previous")
		} else {
			last = d.A[0]
		}
	}
}

func TestDOH(t *testing.T) {
	client := New([]string{"doh:https://doh.opendns.com/dns-query:post", "doh:https://doh.opendns.com/dns-query:get"}, 5)

	d, err := client.QueryMultiple("example.com", []uint16{dns.TypeA})
	require.Nil(t, err)

	// From current dig result
	require.True(t, len(d.A) > 0)
}

func TestDOT(t *testing.T) {
	client := New([]string{"dot:dns.google:853", "dot:1dot1dot1dot1.cloudflare-dns.com"}, 5)

	d, err := client.QueryMultiple("example.com", []uint16{dns.TypeA})
	require.Nil(t, err)

	// From current dig result
	require.True(t, len(d.A) > 0)
}

func TestQueryMultiple(t *testing.T) {
	client := New([]string{"8.8.8.8:53", "1.1.1.1:53"}, 5)

	d, err := client.QueryMultiple("example.com", []uint16{dns.TypeA, dns.TypeAAAA})
	require.Nil(t, err)

	// From current dig result
	require.True(t, len(d.A) > 0)
	require.True(t, len(d.AAAA) > 0)
}

func TestTrace(t *testing.T) {
	client := New([]string{"8.8.8.8:53", "1.1.1.1:53"}, 5)

	_, err := client.Trace("www.projectdiscovery.io", dns.TypeA, 100)
	require.Nil(t, err, "could not resolve dns")
}
