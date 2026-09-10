package retryabledns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeHost = "scanme.test"

func TestDialerLocalAddr(t *testing.T) {
	fr := newFakeResolver(t, dns.RcodeSuccess, arecord(fakeHost, "203.0.113.10"))

	/** Works without LocalAddrIP **/
	options := Options{
		BaseResolvers: []string{fr.Addr()},
		MaxRetries:    3,
		Timeout:       500 * time.Millisecond,
	}
	require.NoError(t, options.Validate())
	client, err := NewWithOptions(options)
	require.NoError(t, err)
	d, err := client.QueryMultiple(fakeHost, []uint16{dns.TypeA})
	require.NoError(t, err)
	require.Equal(t, []string{"203.0.113.10"}, d.A)

	/** Errors with invalid LocalAddrIP **/
	// 1.2.3.4 is not assigned to any local interface, so the dialer
	// must fail to bind regardless of where the resolver lives.
	options = Options{
		BaseResolvers: []string{fr.Addr()},
		MaxRetries:    3,
		Timeout:       500 * time.Millisecond,
	}
	options.SetLocalAddrIP("1.2.3.4")
	require.NoError(t, options.Validate())
	client, err = NewWithOptions(options)
	require.NoError(t, err)
	_, err = client.QueryMultiple(fakeHost, []uint16{dns.TypeA})
	require.Error(t, err)
}

func TestConsistentResolve(t *testing.T) {
	fr := newFakeResolver(t, dns.RcodeSuccess, arecord(fakeHost, "203.0.113.10"))
	client, err := New([]string{fr.Addr()}, 5)
	require.NoError(t, err)

	for i := 0; i < 10; i++ {
		d, err := client.Resolve(fakeHost)
		require.NoError(t, err, "could not resolve dns")
		require.Equal(t, []string{"203.0.113.10"}, d.A, "iteration %d returned different data", i)
	}
}

func TestUDP(t *testing.T) {
	fr := newFakeResolver(t, dns.RcodeSuccess, arecord(fakeHost, "203.0.113.10"))
	client, err := New([]string{"udp:" + fr.Addr()}, 5)
	require.NoError(t, err)

	d, err := client.QueryMultiple(fakeHost, []uint16{dns.TypeA})
	require.NoError(t, err)
	require.NotEmpty(t, d.A)
}

func TestTCP(t *testing.T) {
	fr := newFakeResolverTCP(t, dns.RcodeSuccess, arecord(fakeHost, "203.0.113.10"))
	client, err := New([]string{"tcp:" + fr.Addr()}, 5)
	require.NoError(t, err)

	d, err := client.QueryMultiple(fakeHost, []uint16{dns.TypeA})
	require.NoError(t, err)
	require.NotEmpty(t, d.A)
}

func TestDOH(t *testing.T) {
	fd := newFakeDoHResolver(t, dns.RcodeSuccess, arecord(fakeHost, "203.0.113.10"))

	for _, method := range []string{"post", "get"} {
		t.Run(method, func(t *testing.T) {
			client, err := New([]string{fd.ResolverString(method)}, 5)
			require.NoError(t, err)
			d, err := client.QueryMultiple(fakeHost, []uint16{dns.TypeA})
			require.NoError(t, err)
			require.NotEmpty(t, d.A)
		})
	}
}

// TestDOT is intentionally an integration test against public DoT
// resolvers because the retryabledns client builds its internal dot
// client without a configurable *tls.Config, so we can't accept a
// self-signed cert from an in-process server. It's gated by
// testing.Short so it stays out of unit-test runs.
func TestDOT(t *testing.T) {
	if testing.Short() {
		t.Skip("DOT test requires real network in -short mode")
	}
	client, err := New(
		[]string{"dot:dns.google:853", "dot:1dot1dot1dot1.cloudflare-dns.com"}, 5,
	)
	require.NoError(t, err)
	d, err := client.QueryMultiple("scanme.sh", []uint16{dns.TypeA})
	require.NoError(t, err)
	require.NotEmpty(t, d.A)
}

func TestQueryMultiple(t *testing.T) {
	fr := newFakeResolverFunc(t, rrByQtype(map[uint16][]dns.RR{
		dns.TypeA:    {arecord(fakeHost, "203.0.113.10")},
		dns.TypeAAAA: {aaaarecord(fakeHost, "2001:db8::1")},
		dns.TypeSOA:  {soarecord(fakeHost)},
	}))

	client, err := New([]string{fr.Addr()}, 5)
	require.NoError(t, err)

	d, err := client.QueryMultiple(fakeHost, []uint16{
		dns.TypeA,
		dns.TypeAAAA,
		dns.TypeSOA,
	})
	require.NoError(t, err)
	require.Equal(t, []string{"203.0.113.10"}, d.A)
	require.Equal(t, []string{"2001:db8::1"}, d.AAAA)
	require.Len(t, d.SOA, 1)
	require.NotZero(t, d.TTL)
}

func TestRetries(t *testing.T) {
	dead := freeUDPAddr(t)
	client, err := New([]string{dead}, 5)
	require.NoError(t, err)

	// QueryMultiple path: ErrRetriesExceeded after exhausting retries
	// against an unbound port.
	_, err = client.QueryMultiple(fakeHost, []uint16{dns.TypeA})
	require.ErrorIs(t, err, ErrRetriesExceeded)

	// Do() path: same expectation via the raw interface.
	msg := &dns.Msg{}
	msg.Id = dns.Id()
	msg.SetEdns0(4096, false)
	msg.Question = []dns.Question{{
		Name:   dns.Fqdn(fakeHost),
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}}
	msg.RecursionDesired = true
	_, err = client.Do(msg)
	require.ErrorIs(t, err, ErrRetriesExceeded)
}

func TestNoRecords(t *testing.T) {
	// A resolver that answers NOERROR but with no records: the
	// canonical "host exists but no A/AAAA" path.
	fr := newFakeResolverFunc(t, rrByQtype(map[uint16][]dns.RR{
		// No entries: handler returns SUCCESS with empty Answer.
	}))
	client, err := New([]string{fr.Addr()}, 5)
	require.NoError(t, err)

	res, err := client.QueryMultiple("donotexist."+fakeHost, []uint16{
		dns.TypeA,
		dns.TypeAAAA,
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Empty(t, res.A)
	assert.Empty(t, res.AAAA)
}

// TestTrace remains a network-dependent integration test: it walks the
// DNS root servers from RootDNSServersIPv4 and follows referrals,
// which is not feasible to replicate with a local fake. Guard with
// testing.Short so unit-test runs stay offline.
func TestTrace(t *testing.T) {
	if testing.Short() {
		t.Skip("Trace test requires real DNS roots in -short mode")
	}
	client, err := New([]string{"8.8.8.8:53", "1.1.1.1:53"}, 5)
	require.NoError(t, err)
	_, err = client.Trace("www.projectdiscovery.io", dns.TypeA, 100)
	require.NoError(t, err)
}

func TestAXFRWithUDPResolvers(t *testing.T) {
	// Resolver address configured without a tcp: prefix defaults to
	// UDP. AXFR is TCP-only, so axfr() must force TCP on the fallback
	// path - we verify that by starting a TCP-only AXFR server and
	// passing its address as a plain (UDP-by-default) resolver string.
	// AXFR protocol requires the zone to start and end with an SOA.
	records := []dns.RR{
		soarecord("zonetransfer.test"),
		arecord("ns1.zonetransfer.test", "203.0.113.1"),
		arecord("host.zonetransfer.test", "203.0.113.2"),
		soarecord("zonetransfer.test"),
	}
	fr := newFakeAXFRResolver(t, records)

	client, err := New([]string{fr.Addr()}, 3)
	require.NoError(t, err)

	axfrData, err := client.AXFR("zonetransfer.test")
	require.NoError(t, err)
	require.NotNil(t, axfrData)
	require.NotEmpty(t, axfrData.DNSData, "expected AXFR records but got none")

	var totalRecords int
	for _, d := range axfrData.DNSData {
		totalRecords += len(d.AllRecords)
	}
	require.Greater(t, totalRecords, 0, "expected non-empty AXFR records")
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

	fr := newFakeResolverFunc(t, rrByQtype(nil))
	options := Options{
		BaseResolvers: []string{fr.Addr()},
		MaxRetries:    3,
		Timeout:       500 * time.Millisecond,
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

	fr := newFakeResolverFunc(t, rrByQtype(nil))
	options := Options{
		BaseResolvers: []string{fr.Addr()},
		MaxRetries:    3,
		Timeout:       500 * time.Millisecond,
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
