package doh

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// newFakeDoH starts an httptest TLS server that answers both styles of
// DoH request used by this package:
//   - "application/dns-json" (the JSON API used by QueryWithJsonAPI)
//   - "application/dns-message" (RFC 8484 wire format, GET via ?dns= or POST body)
//
// It always returns the provided IPv4 address as a single A record.
// The returned server's *http.Client trusts the test certificate.
func newFakeDoH(t *testing.T, ip string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// JSON API path: clients set Accept: application/dns-json and
		// pass name/type as query params.
		if strings.Contains(r.Header.Get("Accept"), "application/dns-json") {
			name := r.URL.Query().Get("name")
			resp := Response{
				Status: 0,
				Question: []Question{{
					Name: dns.Fqdn(name),
					Type: int(dns.TypeA),
				}},
				Answer: []Answer{{
					Name: dns.Fqdn(name),
					Type: int(dns.TypeA),
					TTL:  60,
					Data: ip,
				}},
			}
			w.Header().Set("Content-Type", "application/dns-json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		// Wire format path: parse the DNS message from either ?dns= or
		// the body and reply with a single A record.
		var body []byte
		var err error
		switch r.Method {
		case http.MethodGet:
			body, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		default:
			body, err = io.ReadAll(r.Body)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req := &dns.Msg{}
		if err := req.Unpack(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		name := req.Question[0].Name
		msg := &dns.Msg{}
		msg.SetReply(req)
		msg.Rcode = dns.RcodeSuccess
		msg.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   parseIPv4(ip),
			},
		}
		out, err := msg.Pack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func parseIPv4(s string) []byte {
	var ip [4]byte
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil
	}
	for i, p := range parts {
		var v int
		for _, c := range p {
			if c < '0' || c > '9' {
				return nil
			}
			v = v*10 + int(c-'0')
		}
		if v < 0 || v > 255 {
			return nil
		}
		ip[i] = byte(v)
	}
	return ip[:]
}

func newFakeClient(t *testing.T, ip string) *Client {
	t.Helper()
	srv := newFakeDoH(t, ip)
	return NewWithOptions(Options{
		DefaultResolver: Resolver{Name: "fake", URL: srv.URL},
		HttpClient:      srv.Client(),
	})
}

func TestConsistentResolve(t *testing.T) {
	client := newFakeClient(t, "203.0.113.10")
	var lastAnswer string
	for i := 0; i < 10; i++ {
		d, err := client.Query("scanme.test", A)
		require.NoError(t, err, "could not resolve dns")
		require.NotEmpty(t, d.Answer, "expected at least one answer")
		if lastAnswer == "" {
			lastAnswer = d.Answer[0].Data
		} else {
			require.Equal(t, lastAnswer, d.Answer[0].Data, "got another data from previous")
		}
	}
}

func TestResolvers(t *testing.T) {
	srv := newFakeDoH(t, "203.0.113.10")
	client := NewWithOptions(Options{
		DefaultResolver: Resolver{Name: "fake", URL: srv.URL},
		HttpClient:      srv.Client(),
	})
	fakeResolver := Resolver{Name: "fake", URL: srv.URL}

	d, err := client.QueryWithDOH(MethodGet, fakeResolver, "www.example.com", dns.TypeA)
	require.NoError(t, err)
	require.NotNil(t, d)
	require.NotEmpty(t, d.Answer, "GET path must return an answer")

	d, err = client.QueryWithDOH(MethodPost, fakeResolver, "www.example.com", dns.TypeA)
	require.NoError(t, err)
	require.NotNil(t, d)
	require.NotEmpty(t, d.Answer, "POST path must return an answer")
}
