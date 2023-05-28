package retryabledns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDialerLocalAddr(t *testing.T) {
	/** Works without LocalAddrIP **/
	options := Options{
		BaseResolvers: []string{"1.1.1.1:53", "udp:8.8.8.8"},
		MaxRetries:    3,
	}
	err := options.Validate()
	require.Nil(t, err)
	client, _ := NewWithOptions(options)
	d, err := client.QueryMultiple("example.com", []uint16{dns.TypeA})
	require.Nil(t, err)
	// From current dig result
	require.True(t, len(d.A) > 0)

	/** Errors with invalid LocalAddrIP **/
	options = Options{
		BaseResolvers: []string{"1.1.1.1:53", "udp:8.8.8.8"},
		MaxRetries:    3,
	}
	options.SetLocalAddrIP("1.2.3.4")
	err = options.Validate()
	require.Nil(t, err)
	client, _ = NewWithOptions(options)
	_, err = client.QueryMultiple("example.com", []uint16{dns.TypeA})
	require.NotNil(t, err)

	/** Does not error with valid Local IP **/
	// options = Options{
	// 	BaseResolvers: []string{"1.1.1.1:53", "udp:8.8.8.8"},
	// 	MaxRetries:    3,
	// }
	// err = options.SetLocalAddrIPFromNetInterface("en0")
	// require.Nil(t, err)
	// err = options.Validate()
	// require.Nil(t, err)
	// client, _ = NewWithOptions(options)
	// _, err = client.QueryMultiple("example.com", []uint16{dns.TypeA})
	// require.Nil(t, err)
	// // From current dig result
	// require.True(t, len(d.A) > 0)
}

func TestConsistentResolve(t *testing.T) {
	client, _ := New([]string{"8.8.8.8:53", "1.1.1.1:53"}, 5)

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

func TestUDP(t *testing.T) {
	client, _ := New([]string{"1.1.1.1:53", "udp:8.8.8.8"}, 5)

	d, err := client.QueryMultiple("example.com", []uint16{dns.TypeA})
	require.Nil(t, err)

	// From current dig result
	require.True(t, len(d.A) > 0)
}

func TestTCP(t *testing.T) {
	client, _ := New([]string{"tcp:1.1.1.1:53", "tcp:8.8.8.8"}, 5)

	d, err := client.QueryMultiple("example.com", []uint16{dns.TypeA})
	require.Nil(t, err)

	// From current dig result
	require.True(t, len(d.A) > 0)
}

func TestDOH(t *testing.T) {
	client, _ := New([]string{"doh:https://doh.opendns.com/dns-query:post", "doh:https://doh.opendns.com/dns-query:get"}, 5)

	d, err := client.QueryMultiple("example.com", []uint16{dns.TypeA})
	require.Nil(t, err)

	// From current dig result
	require.True(t, len(d.A) > 0)
}

func TestDOT(t *testing.T) {
	client, _ := New([]string{"dot:dns.google:853", "dot:1dot1dot1dot1.cloudflare-dns.com"}, 5)

	d, err := client.QueryMultiple("example.com", []uint16{dns.TypeA})
	require.Nil(t, err)

	// From current dig result
	require.True(t, len(d.A) > 0)
}

func TestQueryMultiple(t *testing.T) {
	client, _ := New([]string{"8.8.8.8:53", "1.1.1.1:53"}, 5)

	// Test various query types
	d, err := client.QueryMultiple("scanme.sh", []uint16{
		dns.TypeA,
		dns.TypeAAAA,
		dns.TypeSOA,
	})
	require.Nil(t, err)

	// From current dig result
	require.True(t, len(d.A) > 0)
	require.True(t, len(d.AAAA) > 0)
	require.True(t, len(d.SOA) > 0)
	require.NotZero(t, d.TTL)
}

func TestTrace(t *testing.T) {
	client, _ := New([]string{"8.8.8.8:53", "1.1.1.1:53"}, 5)

	_, err := client.Trace("www.projectdiscovery.io", dns.TypeA, 100)
	require.Nil(t, err, "could not resolve dns")
}
