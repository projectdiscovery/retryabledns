package retryabledns

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
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
		d, err := client.Resolve("scanme.sh")
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

	d, err := client.QueryMultiple("scanme.sh", []uint16{dns.TypeA})
	require.Nil(t, err)

	// From current dig result
	require.True(t, len(d.A) > 0)
}

func TestTCP(t *testing.T) {
	client, _ := New([]string{"tcp:1.1.1.1:53", "tcp:8.8.8.8"}, 5)

	d, err := client.QueryMultiple("scanme.sh", []uint16{dns.TypeA})
	require.Nil(t, err)

	// From current dig result
	require.True(t, len(d.A) > 0)
}

func TestDOH(t *testing.T) {
	client, _ := New([]string{"doh:https://doh.opendns.com/dns-query:post", "doh:https://doh.opendns.com/dns-query:get"}, 5)

	d, err := client.QueryMultiple("scanme.sh", []uint16{dns.TypeA})
	require.Nil(t, err)

	// From current dig result
	require.True(t, len(d.A) > 0)
}

func TestDOT(t *testing.T) {
	client, _ := New([]string{"dot:dns.google:853", "dot:1dot1dot1dot1.cloudflare-dns.com"}, 5)

	d, err := client.QueryMultiple("scanme.sh", []uint16{dns.TypeA})
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

func TestRetries(t *testing.T) {
	client, _ := New([]string{"127.0.0.1"}, 5)

	// Test that error is returned on max retries, should conn refused 5 times then err
	_, err := client.QueryMultiple("scanme.sh", []uint16{dns.TypeA})
	require.ErrorIs(t, err, ErrRetriesExceeded)

	msg := &dns.Msg{}
	msg.Id = dns.Id()
	msg.SetEdns0(4096, false)
	msg.Question = make([]dns.Question, 1)
	msg.RecursionDesired = true
	question := dns.Question{
		Name:   "scanme.sh",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}
	msg.Question[0] = question

	// Test with raw Do() interface as well
	_, err = client.Do(msg)
	require.True(t, err == ErrRetriesExceeded)
}

func TestNoRecords(t *testing.T) {
	client, err := New([]string{"8.8.8.8:53", "1.1.1.1:53"}, 5)
	require.NoError(t, err)

	// Test various query types
	res, err := client.QueryMultiple("donotexist.scanme.sh", []uint16{
		dns.TypeA,
		dns.TypeAAAA,
	})
	require.NoError(t, err)
	require.NotNil(t, res)

	assert.Empty(t, res.A)
	assert.Empty(t, res.AAAA)
}

func TestTrace(t *testing.T) {
	client, _ := New([]string{"8.8.8.8:53", "1.1.1.1:53"}, 5)

	_, err := client.Trace("www.projectdiscovery.io", dns.TypeA, 100)
	require.Nil(t, err, "could not resolve dns")
}

func TestAXFRWithUDPResolvers(t *testing.T) {
	// Resolver configured without tcp: prefix defaults to UDP.
	// AXFR requires TCP, so axfr() must force TCP on fallback resolvers.
	client, err := New([]string{"81.4.108.41:53"}, 3)
	require.NoError(t, err)

	axfrData, err := client.AXFR("zonetransfer.me")
	require.NoError(t, err)
	require.NotNil(t, axfrData)
	require.True(t, len(axfrData.DNSData) > 0, "expected AXFR records but got none")

	var totalRecords int
	for _, d := range axfrData.DNSData {
		totalRecords += len(d.AllRecords)
	}
	require.True(t, totalRecords > 0, "expected non-empty AXFR records")
}

func TestParseFromMsgIgnoresExtraAndNsSections(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{93, 184, 216, 34},
		},
	}

	msg.Ns = []dns.RR{
		&dns.NS{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
			Ns:  "ns1.example.com.",
		},
		&dns.SOA{
			Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:      "ns1.example.com.",
			Mbox:    "admin.example.com.",
			Serial:  2024010101,
			Refresh: 7200,
			Retry:   3600,
			Expire:  1209600,
			Minttl:  300,
		},
	}

	msg.Extra = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   []byte{198, 51, 100, 1},
		},
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "ns1.example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600},
			AAAA: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},
		},
	}

	d := &DNSData{}
	err := d.ParseFromMsg(msg)
	require.NoError(t, err)

	assert.Equal(t, []string{"93.184.216.34"}, d.A, "only Answer A records should be parsed")
	assert.Empty(t, d.AAAA, "Additional AAAA glue records should not leak")
	assert.Empty(t, d.NS, "Authority NS records should not leak")
	assert.Empty(t, d.SOA, "Authority SOA records should not leak")
}

func TestInternalIPDetectionWithHostsFile(t *testing.T) {
	CheckInternalIPs = true
	defer func() { CheckInternalIPs = false }()

	options := Options{
		BaseResolvers: []string{"8.8.8.8:53"},
		MaxRetries:    3,
		Hostsfile:     true,
	}

	client, err := NewWithOptions(options)
	require.NoError(t, err)

	client.knownHosts = map[string][]string{
		"localhost":     {"127.0.0.1", "::1"},
		"internal.test": {"192.168.1.100", "10.0.0.1"},
		"external.test": {"8.8.8.8"},
	}

	testCases := []struct {
		host               string
		expectedInternal   bool
		expectedInternalIP []string
	}{
		{
			host:               "localhost",
			expectedInternal:   true,
			expectedInternalIP: []string{"127.0.0.1", "::1"},
		},
		{
			host:               "internal.test",
			expectedInternal:   true,
			expectedInternalIP: []string{"192.168.1.100", "10.0.0.1"},
		},
		{
			host:             "external.test",
			expectedInternal: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.host, func(t *testing.T) {
			result, err := client.QueryMultiple(tc.host, []uint16{dns.TypeA, dns.TypeAAAA})
			require.NoError(t, err)
			require.True(t, result.HostsFile)

			if tc.expectedInternal {
				assert.True(t, result.HasInternalIPs, "HasInternalIPs should be true for %s", tc.host)
				assert.ElementsMatch(t, tc.expectedInternalIP, result.InternalIPs, "InternalIPs should match for %s", tc.host)
			} else {
				assert.False(t, result.HasInternalIPs, "HasInternalIPs should be false for %s", tc.host)
				assert.Empty(t, result.InternalIPs, "InternalIPs should be empty for %s", tc.host)
			}
		})
	}
}

func TestInternalIPDetectionJSONOutput(t *testing.T) {
	CheckInternalIPs = true
	defer func() { CheckInternalIPs = false }()

	options := Options{
		BaseResolvers: []string{"8.8.8.8:53"},
		MaxRetries:    3,
		Hostsfile:     true,
	}

	client, err := NewWithOptions(options)
	require.NoError(t, err)

	client.knownHosts = map[string][]string{
		"localhost": {"127.0.0.1"},
	}

	result, err := client.QueryMultiple("localhost", []uint16{dns.TypeA})
	require.NoError(t, err)

	jsonOutput, err := result.JSON()
	require.NoError(t, err)

	t.Logf("JSON output for localhost with internal IP detection:\n%s", jsonOutput)

	assert.Contains(t, jsonOutput, `"has_internal_ips":true`)
	assert.Contains(t, jsonOutput, `"internal_ips":["127.0.0.1"]`)
	assert.Contains(t, jsonOutput, `"hosts_file":true`)
}
