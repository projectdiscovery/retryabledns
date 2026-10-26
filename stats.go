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
// All counters, including lastError, are updated lock-free.
type resolverStats struct {
	requests      atomic.Uint64
	successes     atomic.Uint64
	errors        atomic.Uint64
	totalDuration atomic.Int64 // nanoseconds
	lastLatency   atomic.Int64 // nanoseconds
	lastError     atomic.Pointer[error]
}

func (rs *resolverStats) record(duration time.Duration, err error) {
	rs.requests.Add(1)
	rs.totalDuration.Add(duration.Nanoseconds())
	rs.lastLatency.Store(duration.Nanoseconds())
	if err != nil {
		rs.errors.Add(1)
		rs.lastError.Store(&err)
		return
	}
	rs.successes.Add(1)
	if rs.lastError.Load() != nil {
		rs.lastError.Store(nil)
	}
}

func (rs *resolverStats) snapshot(resolver string) ResolverStats {
	reqs := rs.requests.Load()
	total := time.Duration(rs.totalDuration.Load())
	var avg time.Duration
	if reqs > 0 {
		avg = total / time.Duration(reqs)
	}
	var lastErr error
	if p := rs.lastError.Load(); p != nil {
		lastErr = *p
	}
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

// statsRegistry holds the live counters for the resolvers configured in the
// client. Entries are created lazily on first use, but only for the fixed set
// of configured resolvers, so the map is bounded by the configured list.
// Ad-hoc nameservers (Trace referrals, QueryParallel targets, AXFR name
// servers, explicit per-call resolvers) are never recorded.
type statsRegistry struct {
	mu      sync.RWMutex
	entries map[string]*resolverStats
	// allowed is the set of resolver strings that may be recorded. It is
	// built once at construction and is read-only afterwards.
	allowed map[string]struct{}
}

func newStatsRegistry(resolvers ...string) *statsRegistry {
	allowed := make(map[string]struct{}, len(resolvers))
	for _, r := range resolvers {
		if r != "" {
			allowed[r] = struct{}{}
		}
	}
	return &statsRegistry{entries: make(map[string]*resolverStats), allowed: allowed}
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
// of a single attempt. An empty or non-configured resolver is a no-op, so
// callers don't need to guard the "unknown resolver" path and ad-hoc
// nameservers can't grow the map.
func (r *statsRegistry) record(resolver string, duration time.Duration, err error) {
	if _, ok := r.allowed[resolver]; !ok {
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
// accumulated by every attempt the client has issued so far against its
// configured resolvers. The map is keyed by the resolver string (matching
// Resolver.String()) and only holds configured resolvers that have seen at
// least one attempt. Nameservers reached outside the configured list (Trace
// referrals, QueryParallel, AXFR, QueryMultipleWithResolver) are not tracked.
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

// resolverKeys returns the stats keys of the configured resolvers.
func resolverKeys(resolvers []Resolver) []string {
	keys := make([]string, 0, len(resolvers))
	for _, r := range resolvers {
		if r != nil {
			keys = append(keys, r.String())
		}
	}
	return keys
}
