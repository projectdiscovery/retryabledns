package retryabledns

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// fakeResolver is a tiny in-process DNS server used by the test suite
// to assert exact retry-loop behavior without depending on the public
// Internet. Each instance listens on 127.0.0.1 on an ephemeral port
// and is torn down via t.Cleanup.
//
// A single instance can serve UDP, TCP, or both depending on which
// constructor was used.
type fakeResolver struct {
	addr     string
	udp      *dns.Server
	tcp      *dns.Server
	queries  atomic.Int64
	respond  func(*dns.Msg) *dns.Msg
	respAxfr func(*dns.Msg) []dns.RR // optional: when set, AXFR queries stream these records
}

// newFakeResolver starts a UDP server that answers every query with
// the given rcode. When rcode == RcodeSuccess and answer is non-nil,
// the records are returned in the Answer section.
func newFakeResolver(t *testing.T, rcode int, answer ...dns.RR) *fakeResolver {
	t.Helper()
	return newFakeResolverFunc(t, fixedResponse(rcode, answer))
}

// newFakeResolverFunc starts a UDP server with a custom response
// function. Use it when the test needs to vary the rcode or answer
// across consecutive queries.
func newFakeResolverFunc(t *testing.T, respond func(*dns.Msg) *dns.Msg) *fakeResolver {
	t.Helper()
	fr := &fakeResolver{respond: respond}
	fr.startUDP(t, "127.0.0.1:0")
	return fr
}

// newFakeResolverTCP starts a TCP-only server. Used to validate the
// tcp: protocol path of the client.
func newFakeResolverTCP(t *testing.T, rcode int, answer ...dns.RR) *fakeResolver {
	t.Helper()
	fr := &fakeResolver{respond: fixedResponse(rcode, answer)}
	fr.startTCP(t, "127.0.0.1:0")
	return fr
}

// newFakeResolverDualStack starts servers on the same address+port for
// both UDP and TCP. Useful when the test needs to assert that the
// client picks the right transport.
func newFakeResolverDualStack(t *testing.T, respond func(*dns.Msg) *dns.Msg) *fakeResolver {
	t.Helper()
	fr := &fakeResolver{respond: respond}
	fr.startUDP(t, "127.0.0.1:0")
	fr.startTCP(t, fr.addr) // reuse the same address picked by the UDP listener
	return fr
}

// newFakeAXFRResolver starts a dual-stack server that handles the
// full AXFR flow: it answers the NS/A discovery probes over UDP with
// empty NOERROR (so the client falls back to the originally
// configured resolver) and streams the provided records over TCP in
// response to AXFR queries.
func newFakeAXFRResolver(t *testing.T, zoneRecords []dns.RR) *fakeResolver {
	t.Helper()
	emptySuccess := func(req *dns.Msg) *dns.Msg {
		m := &dns.Msg{}
		m.SetReply(req)
		m.Rcode = dns.RcodeSuccess
		return m
	}
	fr := &fakeResolver{
		respond:  emptySuccess,
		respAxfr: func(req *dns.Msg) []dns.RR { return zoneRecords },
	}
	fr.startUDP(t, "127.0.0.1:0")
	fr.startTCP(t, fr.addr)
	return fr
}

func (fr *fakeResolver) Addr() string   { return fr.addr }
func (fr *fakeResolver) Queries() int64 { return fr.queries.Load() }

func (fr *fakeResolver) handle(w dns.ResponseWriter, r *dns.Msg) {
	fr.queries.Add(1)
	// AXFR queries get streamed via dns.Transfer when configured.
	if fr.respAxfr != nil && len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeAXFR {
		tr := new(dns.Transfer)
		ch := make(chan *dns.Envelope, 1)
		ch <- &dns.Envelope{RR: fr.respAxfr(r)}
		close(ch)
		_ = tr.Out(w, r, ch)
		return
	}
	_ = w.WriteMsg(fr.respond(r))
}

func (fr *fakeResolver) startUDP(t *testing.T, addr string) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	p, _ := strconv.Atoi(port)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host), Port: p})
	require.NoError(t, err)
	if fr.addr == "" {
		fr.addr = conn.LocalAddr().String()
	}
	fr.udp = &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(fr.handle)}
	startServer(t, fr.udp)
}

func (fr *fakeResolver) startTCP(t *testing.T, addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	if fr.addr == "" {
		fr.addr = ln.Addr().String()
	}
	fr.tcp = &dns.Server{Listener: ln, Handler: dns.HandlerFunc(fr.handle)}
	startServer(t, fr.tcp)
}

func startServer(t *testing.T, server *dns.Server) {
	t.Helper()
	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = server.Shutdown() })
}

func fixedResponse(rcode int, answer []dns.RR) func(*dns.Msg) *dns.Msg {
	return func(req *dns.Msg) *dns.Msg {
		m := &dns.Msg{}
		m.SetReply(req)
		m.Rcode = rcode
		if rcode == dns.RcodeSuccess && len(answer) > 0 {
			m.Answer = answer
		}
		return m
	}
}

// atomicCounter is a tiny helper for tests that need to drive a fake
// resolver through a deterministic sequence of responses based on the
// number of queries it has already answered.
type atomicCounter struct{ n atomic.Int64 }

func (c *atomicCounter) next() int64 { return c.n.Add(1) }

// arecord builds an A record matching how miekg/dns formats answers.
// Used as the Answer section of synthetic success responses.
func arecord(name, ip string) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: net.ParseIP(ip).To4(),
	}
}

// aaaarecord builds an AAAA record for synthetic success responses.
func aaaarecord(name, ip string) *dns.AAAA {
	return &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		AAAA: net.ParseIP(ip),
	}
}

// soarecord builds a synthetic SOA for tests that exercise TypeSOA.
// The Ns and Mbox fields must be fully qualified, otherwise the
// miekg/dns packer silently produces a malformed response that the
// client cannot read.
func soarecord(name string) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Ns:      dns.Fqdn("ns1." + name),
		Mbox:    dns.Fqdn("admin." + name),
		Serial:  2024010101,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  300,
	}
}

// rrByQtype dispatches to a per-rrtype response factory. It's the
// canonical way to model a server that answers multiple query types
// from the same address.
func rrByQtype(answers map[uint16][]dns.RR) func(*dns.Msg) *dns.Msg {
	return func(req *dns.Msg) *dns.Msg {
		m := &dns.Msg{}
		m.SetReply(req)
		if len(req.Question) == 0 {
			return m
		}
		qt := req.Question[0].Qtype
		records, ok := answers[qt]
		if !ok {
			// Mirror the behavior of a real resolver: success rcode
			// with an empty answer section when no records exist for
			// this type.
			m.Rcode = dns.RcodeSuccess
			return m
		}
		m.Rcode = dns.RcodeSuccess
		m.Answer = records
		return m
	}
}

// freeUDPAddr returns a 127.0.0.1 UDP port that nothing is bound to
// (the listener is opened and immediately closed). It's used to test
// the "connection refused" / "no resolver" retry paths without
// depending on a real network destination.
func freeUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	addr := conn.LocalAddr().String()
	require.NoError(t, conn.Close())
	return addr
}

// -----------------------------------------------------------------------------
// DoH fake server
// -----------------------------------------------------------------------------

// fakeDoHResolver is a tiny in-process DoH endpoint backed by
// httptest.NewTLSServer. The retryabledns DoH client is built with
// InsecureSkipVerify, so the self-signed cert is accepted out of the
// box.
type fakeDoHResolver struct {
	srv     *httptest.Server
	queries atomic.Int64
}

func newFakeDoHResolver(t *testing.T, rcode int, answer ...dns.RR) *fakeDoHResolver {
	t.Helper()
	fd := &fakeDoHResolver{}
	fd.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fd.queries.Add(1)
		body, err := readDoHQuery(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req := &dns.Msg{}
		if err := req.Unpack(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := &dns.Msg{}
		resp.SetReply(req)
		resp.Rcode = rcode
		if rcode == dns.RcodeSuccess && len(answer) > 0 {
			resp.Answer = answer
		}
		out, err := resp.Pack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	t.Cleanup(fd.srv.Close)
	return fd
}

// ResolverString returns the resolver string in the form expected by
// retryabledns ("doh:<url>:<method>"). method must be one of
// "post" / "get" / "jsonapi".
func (fd *fakeDoHResolver) ResolverString(method string) string {
	return "doh:" + fd.srv.URL + "/dns-query:" + method
}

// HostPort returns the host:port of the underlying HTTPS server, used
// when we need it bare (without the doh: prefix).
func (fd *fakeDoHResolver) HostPort() string {
	u, _ := url.Parse(fd.srv.URL)
	return u.Host
}

func (fd *fakeDoHResolver) Queries() int64 { return fd.queries.Load() }

func readDoHQuery(r *http.Request) ([]byte, error) {
	switch r.Method {
	case http.MethodGet:
		return base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
	default:
		return io.ReadAll(r.Body)
	}
}
