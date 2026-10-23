package retryabledns

import (
	"sync"
	"sync/atomic"
	"time"
)

// ResolverStats is a point-in-time snapshot of a single resolver's
// performance counters. Returned by Client.Stats. All fields are safe
// to read; the snapshot does not alias the live counters.
type ResolverStats struct {
	// Resolver is the resolver address/URL these counters refer to.
	Resolver string
	// Requests is the total number of attempts dispatched to this
	// resolver (counts every retry independently).
	Requests uint64
	// Successes is the number of attempts that returned a usable
	// response (no transport/protocol error). A non-success rcode
	// still counts as a success here; rcode handling is the caller's
	// concern.
	Successes uint64
	// Errors is the number of attempts that failed before yielding a
	// response (timeouts, dial failures, malformed replies, ...).
	Errors uint64
	// TotalDuration is the cumulative round-trip time of every
	// recorded attempt (both successes and errors).
	TotalDuration time.Duration
	// AverageDuration is TotalDuration / Requests, or zero if no
	// attempts have been recorded yet.
	AverageDuration time.Duration
	// LastLatency is the round-trip time of the most recent attempt.
	LastLatency time.Duration
	// LastError carries the error of the most recent failed attempt,
	// or nil if the last attempt succeeded (or there were none).
	LastError error
}

// resolverStats is the live, mutable counter set for a single resolver.
// All counters are updated lock-free; LastError is guarded by mu so we
// don't tear an interface value on concurrent writes.
type resolverStats struct {
	requests      atomic.Uint64
	successes     atomic.Uint64
	errors        atomic.Uint64
	totalDuration atomic.Int64 // nanoseconds
	lastLatency   atomic.Int64 // nanoseconds

	mu        sync.Mutex
	lastError error
}

func (rs *resolverStats) record(duration time.Duration, err error) {
	rs.requests.Add(1)
	rs.totalDuration.Add(duration.Nanoseconds())
	rs.lastLatency.Store(duration.Nanoseconds())
	if err != nil {
		rs.errors.Add(1)
		rs.mu.Lock()
		rs.lastError = err
		rs.mu.Unlock()
		return
	}
	rs.successes.Add(1)
	rs.mu.Lock()
	rs.lastError = nil
	rs.mu.Unlock()
}

func (rs *resolverStats) snapshot(resolver string) ResolverStats {
	reqs := rs.requests.Load()
	total := time.Duration(rs.totalDuration.Load())
	var avg time.Duration
	if reqs > 0 {
		avg = total / time.Duration(reqs)
	}
	rs.mu.Lock()
	lastErr := rs.lastError
	rs.mu.Unlock()
	return ResolverStats{
		Resolver:        resolver,
		Requests:        reqs,
		Successes:       rs.successes.Load(),
		Errors:          rs.errors.Load(),
		TotalDuration:   total,
		AverageDuration: avg,
		LastLatency:     time.Duration(rs.lastLatency.Load()),
		LastError:       lastErr,
	}
}

// statsRegistry holds the live counters for every resolver the client
// has issued attempts against. Entries are created lazily on first use.
type statsRegistry struct {
	mu      sync.RWMutex
	entries map[string]*resolverStats
}

func newStatsRegistry() *statsRegistry {
	return &statsRegistry{entries: make(map[string]*resolverStats)}
}

// get returns the counter set for the given resolver, creating it on
// first use.
func (r *statsRegistry) get(resolver string) *resolverStats {
	r.mu.RLock()
	rs, ok := r.entries[resolver]
	r.mu.RUnlock()
	if ok {
		return rs
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if rs, ok = r.entries[resolver]; ok {
		return rs
	}
	rs = &resolverStats{}
	r.entries[resolver] = rs
	return rs
}

// record updates the counters for resolver with the duration and result
// of a single attempt. A nil resolver string is treated as a no-op so
// callers don't need to guard the common "unknown resolver" path.
func (r *statsRegistry) record(resolver string, duration time.Duration, err error) {
	if resolver == "" {
		return
	}
	r.get(resolver).record(duration, err)
}

// snapshot returns the current counter values for every resolver that
// has been observed at least once. The returned map is fully owned by
// the caller.
func (r *statsRegistry) snapshot() map[string]ResolverStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]ResolverStats, len(r.entries))
	for resolver, rs := range r.entries {
		out[resolver] = rs.snapshot(resolver)
	}
	return out
}

// reset drops all counters. New attempts after a reset start from zero.
func (r *statsRegistry) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = make(map[string]*resolverStats)
}

// Stats returns a point-in-time snapshot of the per-resolver counters
// accumulated by every attempt the client has issued so far. The map
// is keyed by the resolver string (matching Resolver.String()).
//
// Stats are tracked automatically; there is no opt-in. Counters are
// updated lock-free so they have negligible cost on the hot path.
func (c *Client) Stats() map[string]ResolverStats {
	return c.stats.snapshot()
}

// ResetStats drops all per-resolver counters. Future attempts start
// from zero. This is purely additive and does not affect resolution
// behavior.
func (c *Client) ResetStats() {
	c.stats.reset()
}

// recordAttempt is the single chokepoint through which resolver
// attempts publish their outcome. It is called from every place in the
// retry loop that issues a transport-level exchange.
func (c *Client) recordAttempt(resolver Resolver, start time.Time, err error) {
	if resolver == nil {
		return
	}
	c.stats.record(resolver.String(), time.Since(start), err)
}
