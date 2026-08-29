package retryabledns

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestStatsRegistry_Record(t *testing.T) {
	reg := newStatsRegistry()
	reg.record("1.1.1.1:53", 10*time.Millisecond, nil)
	reg.record("1.1.1.1:53", 20*time.Millisecond, nil)
	reg.record("1.1.1.1:53", 30*time.Millisecond, errors.New("timeout"))

	snap := reg.snapshot()
	require.Len(t, snap, 1)

	rs := snap["1.1.1.1:53"]
	require.Equal(t, "1.1.1.1:53", rs.Resolver)
	require.Equal(t, uint64(3), rs.Requests)
	require.Equal(t, uint64(2), rs.Successes)
	require.Equal(t, uint64(1), rs.Errors)
	require.Equal(t, 60*time.Millisecond, rs.TotalDuration)
	require.Equal(t, 20*time.Millisecond, rs.AverageDuration)
	require.Equal(t, 30*time.Millisecond, rs.LastLatency)
	require.EqualError(t, rs.LastError, "timeout")
}

func TestStatsRegistry_LastErrorClearedOnSuccess(t *testing.T) {
	reg := newStatsRegistry()
	reg.record("r", time.Millisecond, errors.New("boom"))
	require.EqualError(t, reg.snapshot()["r"].LastError, "boom")

	reg.record("r", time.Millisecond, nil)
	require.NoError(t, reg.snapshot()["r"].LastError)
}

func TestStatsRegistry_MultipleResolvers(t *testing.T) {
	reg := newStatsRegistry()
	reg.record("a", time.Millisecond, nil)
	reg.record("b", 2*time.Millisecond, errors.New("err"))
	reg.record("a", 3*time.Millisecond, nil)

	snap := reg.snapshot()
	require.Len(t, snap, 2)
	require.Equal(t, uint64(2), snap["a"].Requests)
	require.Equal(t, uint64(0), snap["a"].Errors)
	require.Equal(t, uint64(1), snap["b"].Requests)
	require.Equal(t, uint64(1), snap["b"].Errors)
}

func TestStatsRegistry_AverageZeroOnNoRequests(t *testing.T) {
	reg := newStatsRegistry()
	require.Empty(t, reg.snapshot())
}

func TestStatsRegistry_Reset(t *testing.T) {
	reg := newStatsRegistry()
	reg.record("a", time.Millisecond, nil)
	require.NotEmpty(t, reg.snapshot())

	reg.reset()
	require.Empty(t, reg.snapshot())

	// New attempts after a reset start from zero.
	reg.record("a", 5*time.Millisecond, nil)
	require.Equal(t, uint64(1), reg.snapshot()["a"].Requests)
}

func TestStatsRegistry_EmptyResolverNoop(t *testing.T) {
	reg := newStatsRegistry()
	reg.record("", time.Millisecond, nil)
	require.Empty(t, reg.snapshot(), "empty resolver should not create an entry")
}

func TestStatsRegistry_ConcurrentRecord(t *testing.T) {
	reg := newStatsRegistry()
	const goroutines = 50
	const perGoroutine = 200

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				var err error
				if i%2 == 0 {
					err = errors.New("e")
				}
				reg.record("r", time.Microsecond, err)
			}
		}()
	}
	wg.Wait()

	snap := reg.snapshot()["r"]
	require.Equal(t, uint64(goroutines*perGoroutine), snap.Requests)
	require.Equal(t, uint64(goroutines*perGoroutine/2), snap.Successes)
	require.Equal(t, uint64(goroutines*perGoroutine/2), snap.Errors)
}

func TestStatsRegistry_SnapshotIsIndependent(t *testing.T) {
	reg := newStatsRegistry()
	reg.record("r", time.Millisecond, nil)

	snap1 := reg.snapshot()
	reg.record("r", time.Millisecond, nil)
	snap2 := reg.snapshot()

	require.Equal(t, uint64(1), snap1["r"].Requests, "old snapshot must not change")
	require.Equal(t, uint64(2), snap2["r"].Requests)
}

func TestClient_StatsExposed(t *testing.T) {
	client, err := New([]string{"1.1.1.1:53"}, 1)
	require.NoError(t, err)
	require.NotNil(t, client.Stats(), "Stats() must always return a non-nil map")
}

// TestClient_RecordAttemptNilResolver guards the defensive no-op on the
// hot path - some retry branches can leave resolver == nil after a
// type-switch miss; the helper must tolerate it.
func TestClient_RecordAttemptNilResolver(t *testing.T) {
	client, err := New([]string{"1.1.1.1:53"}, 1)
	require.NoError(t, err)
	require.NotPanics(t, func() {
		client.recordAttempt(nil, time.Now(), nil)
	})
	require.Empty(t, client.Stats())
}

// TestClient_QueryRecordsStats is an integration smoke test against
// real public resolvers - it just confirms the wiring: a successful
// query produces at least one recorded success on the chosen resolver.
func TestClient_QueryRecordsStats(t *testing.T) {
	if testing.Short() {
		t.Skip("network test skipped in -short mode")
	}
	client, err := New([]string{"1.1.1.1:53"}, 2)
	require.NoError(t, err)

	_, err = client.QueryMultiple("scanme.sh", []uint16{dns.TypeA})
	require.NoError(t, err)

	stats := client.Stats()
	rs, ok := stats["1.1.1.1:53"]
	require.True(t, ok, "expected stats entry for 1.1.1.1:53, got %v", stats)
	require.GreaterOrEqual(t, rs.Requests, uint64(1))
	require.GreaterOrEqual(t, rs.Successes, uint64(1))
	require.Equal(t, uint64(0), rs.Errors)
	require.Greater(t, rs.AverageDuration, time.Duration(0))
}

// TestClient_QueryRecordsErrorStats verifies the error counter
// increments when the resolver is unreachable.
func TestClient_QueryRecordsErrorStats(t *testing.T) {
	if testing.Short() {
		t.Skip("network test skipped in -short mode")
	}
	// 127.0.0.1:1 is reserved-tcpmux; no DNS responder will answer.
	client, err := NewWithOptions(Options{
		BaseResolvers: []string{"127.0.0.1:1"},
		MaxRetries:    2,
		Timeout:       250 * time.Millisecond,
	})
	require.NoError(t, err)

	_, _ = client.QueryMultiple("scanme.sh", []uint16{dns.TypeA})

	rs, ok := client.Stats()["127.0.0.1:1"]
	require.True(t, ok)
	require.GreaterOrEqual(t, rs.Errors, uint64(1))
	require.Error(t, rs.LastError)
}

func TestClient_ResetStats(t *testing.T) {
	client, err := New([]string{"1.1.1.1:53"}, 1)
	require.NoError(t, err)
	client.stats.record("1.1.1.1:53", time.Millisecond, nil)

	require.NotEmpty(t, client.Stats())
	client.ResetStats()
	require.Empty(t, client.Stats())
}
