package retryabledns

import (
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------------
// Unit tests for the option's predicate
// -----------------------------------------------------------------------------

func TestOptions_ExitOnRcode_DefaultsToSuccessOnly(t *testing.T) {
	var opts Options
	require.True(t, opts.exitOnRcode(dns.RcodeSuccess),
		"empty list must still terminate on RcodeSuccess for backward compatibility")
	require.False(t, opts.exitOnRcode(dns.RcodeNameError),
		"empty list must not terminate on non-success rcodes")
	require.False(t, opts.exitOnRcode(dns.RcodeServerFailure))
	require.False(t, opts.exitOnRcode(dns.RcodeRefused))
}

func TestOptions_ExitOnRcode_RespectsList(t *testing.T) {
	opts := Options{ExitOnStatusCodes: []int{dns.RcodeSuccess, dns.RcodeNameError}}
	require.True(t, opts.exitOnRcode(dns.RcodeSuccess))
	require.True(t, opts.exitOnRcode(dns.RcodeNameError))
	require.False(t, opts.exitOnRcode(dns.RcodeServerFailure))
}

// TestOptions_ExitOnRcode_ListWithoutSuccess proves that an
// ExitOnStatusCodes list that excludes RcodeSuccess fully overrides the
// default ("success terminates") - this is a deliberate, documented
// consequence of treating the list as the source of truth.
func TestOptions_ExitOnRcode_ListWithoutSuccess(t *testing.T) {
	opts := Options{ExitOnStatusCodes: []int{dns.RcodeServerFailure}}
	require.False(t, opts.exitOnRcode(dns.RcodeSuccess))
	require.True(t, opts.exitOnRcode(dns.RcodeServerFailure))
}

// -----------------------------------------------------------------------------
// Legacy-behavior regression suite (Options.ExitOnStatusCodes == nil)
//
// These tests pin the historical contract so any future refactor of the
// retry loop has to keep producing the same observable behavior for
// callers who have not opted into the new option.
// -----------------------------------------------------------------------------

func newLegacyClient(t *testing.T, resolvers ...string) *Client {
	t.Helper()
	c, err := NewWithOptions(Options{
		BaseResolvers: resolvers,
		MaxRetries:    3,
		Timeout:       500 * time.Millisecond,
	})
	require.NoError(t, err)
	return c
}

func TestLegacy_SuccessOnFirstAttempt(t *testing.T) {
	ok := newFakeResolver(t, dns.RcodeSuccess, arecord("scanme.sh", "203.0.113.10"))
	client := newLegacyClient(t, ok.Addr())

	d, err := client.QueryMultiple("scanme.sh", []uint16{dns.TypeA})
	require.NoError(t, err)
	require.Equal(t, []string{"203.0.113.10"}, d.A)
	require.Equal(t, "NOERROR", d.StatusCode)
	require.Equal(t, []string{ok.Addr()}, d.Resolver,
		"resolver list must contain exactly the resolver that answered")
	require.EqualValues(t, 1, ok.Queries(),
		"loop must break on the first success and not retry")
}

func TestLegacy_NxdomainExhaustsRetriesAndAccumulates(t *testing.T) {
	nx := newFakeResolver(t, dns.RcodeNameError)
	client := newLegacyClient(t, nx.Addr())

	d, err := client.QueryMultiple("missing.example", []uint16{dns.TypeA})
	require.NoError(t, err, "legacy path returns nil error even when all attempts are NXDOMAIN")
	require.Equal(t, "NXDOMAIN", d.StatusCode)
	require.EqualValues(t, 3, nx.Queries(),
		"every retry attempt must hit the resolver under legacy semantics")
	// Legacy semantics: every attempt appends its resolver and
	// concatenates its raw text into dnsdata.
	require.Len(t, d.Resolver, 3,
		"legacy path appends the resolver on every NXDOMAIN attempt")
	require.GreaterOrEqual(t, strings.Count(d.Raw, "NXDOMAIN"), 2,
		"legacy path accumulates Raw text from every attempt")
}

func TestLegacy_NxdomainThenSuccessIsPolluted(t *testing.T) {
	// Two distinct fake resolvers so dedupe() can't collapse the
	// Resolver list. The client's internal round-robin uses a
	// post-incremented index, so with [ok, nx] the first attempt hits
	// nx (NXDOMAIN, skipped+appended), the second hits ok (SUCCESS).
	nx := newFakeResolver(t, dns.RcodeNameError)
	ok := newFakeResolver(t, dns.RcodeSuccess, arecord("scanme.sh", "203.0.113.10"))
	client := newLegacyClient(t, ok.Addr(), nx.Addr())

	d, err := client.QueryMultiple("scanme.sh", []uint16{dns.TypeA})
	require.NoError(t, err)
	require.Equal(t, []string{"203.0.113.10"}, d.A)
	// Documenting the current (pre-fix) pollution so a future change
	// to make this opt-in must be intentional.
	require.ElementsMatch(t, []string{nx.Addr(), ok.Addr()}, d.Resolver,
		"legacy path keeps the NXDOMAIN resolver in the list alongside the success one")
	require.Contains(t, d.Raw, "NXDOMAIN")
	require.Contains(t, d.Raw, "NOERROR")
	require.EqualValues(t, 1, nx.Queries())
	require.EqualValues(t, 1, ok.Queries())
}

func TestLegacy_DoSurfacesLastNxdomainResponse(t *testing.T) {
	nx := newFakeResolver(t, dns.RcodeNameError)
	client := newLegacyClient(t, nx.Addr())

	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn("missing.example"), dns.TypeA)
	resp, err := client.Do(msg)

	require.ErrorIs(t, err, ErrRetriesExceeded)
	require.NotNil(t, resp,
		"legacy Do must surface the last NXDOMAIN response so callers can inspect the rcode")
	require.Equal(t, dns.RcodeNameError, resp.Rcode)
}

// -----------------------------------------------------------------------------
// New-behavior suite (ExitOnStatusCodes set)
//
// All of the cases below would behave differently from the legacy suite
// above. Together with the legacy tests they prove that the option
// strictly adds new behavior without altering any existing path.
// -----------------------------------------------------------------------------

func newExitClient(t *testing.T, exitOn []int, resolvers ...string) *Client {
	t.Helper()
	c, err := NewWithOptions(Options{
		BaseResolvers:     resolvers,
		MaxRetries:        3,
		Timeout:           500 * time.Millisecond,
		ExitOnStatusCodes: exitOn,
	})
	require.NoError(t, err)
	return c
}

func TestExit_OnlySuccess_NxdomainProducesEmptyData(t *testing.T) {
	nx := newFakeResolver(t, dns.RcodeNameError)
	client := newExitClient(t, []int{dns.RcodeSuccess}, nx.Addr())

	d, err := client.QueryMultiple("missing.example", []uint16{dns.TypeA})
	require.NoError(t, err)
	require.NotNil(t, d)
	require.Empty(t, d.StatusCode, "non-definitive rcode must not pollute StatusCode")
	require.Empty(t, d.Resolver, "non-definitive attempts must not append to Resolver")
	require.Empty(t, d.Raw, "non-definitive attempts must not accumulate Raw text")
	require.Empty(t, d.A)
	require.EqualValues(t, 3, nx.Queries(),
		"loop still runs all retries; only the data path is suppressed")
}

func TestExit_OnlySuccess_NxdomainThenSuccessRecordsOnlyWinner(t *testing.T) {
	// Direct contrast against TestLegacy_NxdomainThenSuccessIsPolluted:
	// same resolver setup, opting into ExitOnStatusCodes makes the
	// NXDOMAIN attempt invisible in dnsdata.
	nx := newFakeResolver(t, dns.RcodeNameError)
	ok := newFakeResolver(t, dns.RcodeSuccess, arecord("scanme.sh", "203.0.113.10"))
	client := newExitClient(t, []int{dns.RcodeSuccess}, ok.Addr(), nx.Addr())

	d, err := client.QueryMultiple("scanme.sh", []uint16{dns.TypeA})
	require.NoError(t, err)
	require.Equal(t, []string{"203.0.113.10"}, d.A)
	require.Equal(t, []string{ok.Addr()}, d.Resolver,
		"only the resolver that returned the definitive rcode must be recorded")
	require.NotContains(t, d.Raw, "NXDOMAIN",
		"non-definitive responses must never appear in Raw")
	require.Contains(t, d.Raw, "NOERROR")
	require.EqualValues(t, 1, nx.Queries(), "the NXDOMAIN attempt still happens, just isn't recorded")
	require.EqualValues(t, 1, ok.Queries())
}

func TestExit_IncludesNxdomain_BreaksOnFirstAttempt(t *testing.T) {
	nx := newFakeResolver(t, dns.RcodeNameError)
	client := newExitClient(t, []int{dns.RcodeSuccess, dns.RcodeNameError}, nx.Addr())

	d, err := client.QueryMultiple("missing.example", []uint16{dns.TypeA})
	require.NoError(t, err)
	require.Equal(t, "NXDOMAIN", d.StatusCode,
		"NXDOMAIN must be captured when explicitly listed")
	require.EqualValues(t, 1, nx.Queries(),
		"loop must break on the first definitive attempt; no extra retries")
	require.Len(t, d.Resolver, 1)
}

func TestExit_OnlyServfail_OtherRcodesAreSkipped(t *testing.T) {
	// First attempt returns NXDOMAIN (skipped), second returns
	// SERVFAIL (matches the exit list and terminates the loop).
	var calls atomicCounter
	fr := newFakeResolverFunc(t, func(req *dns.Msg) *dns.Msg {
		m := &dns.Msg{}
		m.SetReply(req)
		if calls.next() == 1 {
			m.Rcode = dns.RcodeNameError
		} else {
			m.Rcode = dns.RcodeServerFailure
		}
		return m
	})
	client := newExitClient(t, []int{dns.RcodeServerFailure}, fr.Addr())

	d, err := client.QueryMultiple("anything.example", []uint16{dns.TypeA})
	require.NoError(t, err)
	require.Equal(t, "SERVFAIL", d.StatusCode,
		"arbitrary rcodes can be promoted to definitive via ExitOnStatusCodes")
	require.Len(t, d.Resolver, 1,
		"only the definitive (SERVFAIL) attempt must appear in the resolver list")
	require.EqualValues(t, 2, fr.Queries(),
		"the skipped NXDOMAIN attempt must still happen; SERVFAIL terminates after it")
}

func TestExit_OnlySuccess_StillSucceedsImmediately(t *testing.T) {
	ok := newFakeResolver(t, dns.RcodeSuccess, arecord("scanme.sh", "203.0.113.10"))
	client := newExitClient(t, []int{dns.RcodeSuccess}, ok.Addr())

	d, err := client.QueryMultiple("scanme.sh", []uint16{dns.TypeA})
	require.NoError(t, err)
	require.Equal(t, []string{"203.0.113.10"}, d.A)
	require.EqualValues(t, 1, ok.Queries(),
		"successful resolution must not trigger extra retries under the new option")
}

func TestExit_Do_SuppressesTrailingNonDefinitive(t *testing.T) {
	nx := newFakeResolver(t, dns.RcodeNameError)
	client := newExitClient(t, []int{dns.RcodeSuccess}, nx.Addr())

	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn("missing.example"), dns.TypeA)
	resp, err := client.Do(msg)

	require.ErrorIs(t, err, ErrRetriesExceeded)
	require.Nil(t, resp,
		"non-definitive trailing response must be suppressed when ExitOnStatusCodes is set")
}

func TestExit_Do_ReturnsDefinitiveResponse(t *testing.T) {
	nx := newFakeResolver(t, dns.RcodeNameError)
	client := newExitClient(t, []int{dns.RcodeNameError}, nx.Addr())

	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn("missing.example"), dns.TypeA)
	resp, err := client.Do(msg)

	require.NoError(t, err,
		"Do must return success when the rcode is in ExitOnStatusCodes")
	require.NotNil(t, resp)
	require.Equal(t, dns.RcodeNameError, resp.Rcode)
}
