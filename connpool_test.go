package retryabledns

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

const connPoolTestTimeout = time.Second

type connPoolExchangeResult struct {
	response *dns.Msg
	err      error
}

func testConnPool(t *testing.T, resolver *fakeResolver) *ConnPool {
	t.Helper()
	host, port, err := net.SplitHostPort(resolver.Addr())
	require.NoError(t, err)
	pool, err := NewConnPool(NetworkResolver{Protocol: UDP, Host: host, Port: port}, 1)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func exchangeWithPool(pool *ConnPool, ctx context.Context) <-chan connPoolExchangeResult {
	result := make(chan connPoolExchangeResult, 1)
	go func() {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(fakeHost), dns.TypeA)
		client := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
		response, _, err := pool.Exchange(ctx, client, msg)
		result <- connPoolExchangeResult{response: response, err: err}
	}()
	return result
}

func awaitPoolExchange(t *testing.T, result <-chan connPoolExchangeResult) connPoolExchangeResult {
	t.Helper()
	select {
	case exchange := <-result:
		return exchange
	case <-time.After(connPoolTestTimeout):
		t.Fatal("pool exchange did not return")
		return connPoolExchangeResult{}
	}
}

func TestConnPoolExchange(t *testing.T) {
	resolver := newFakeResolver(t, dns.RcodeSuccess, arecord(fakeHost, "203.0.113.10"))
	pool := testConnPool(t, resolver)

	for i := 0; i < 2; i++ {
		result := awaitPoolExchange(t, exchangeWithPool(pool, context.Background()))
		require.NoError(t, result.err)
		require.Len(t, result.response.Answer, 1)
		require.Equal(t, "203.0.113.10", result.response.Answer[0].(*dns.A).A.String())
	}
}

func TestConnPoolExchangeAfterClose(t *testing.T) {
	resolver := newFakeResolver(t, dns.RcodeSuccess)
	pool := testConnPool(t, resolver)
	pool.Close()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := awaitPoolExchange(t, exchangeWithPool(pool, ctx))
	require.ErrorIs(t, result.err, context.Canceled)
	require.Nil(t, result.response)
	require.Zero(t, resolver.Queries())
}

func TestConnPoolCloseDuringExchange(t *testing.T) {
	queryReceived := make(chan struct{})
	releaseResponse := make(chan struct{})
	resolver := newFakeResolverFunc(t, func(msg *dns.Msg) *dns.Msg {
		close(queryReceived)
		<-releaseResponse
		return fixedResponse(dns.RcodeSuccess, nil)(msg)
	})
	t.Cleanup(func() { close(releaseResponse) })
	pool := testConnPool(t, resolver)
	result := exchangeWithPool(pool, context.Background())

	select {
	case <-queryReceived:
	case <-time.After(connPoolTestTimeout):
		t.Fatal("resolver did not receive the pool exchange")
	}
	pool.Close()

	require.Error(t, awaitPoolExchange(t, result).err)
}

func TestConnPoolCloseWithWaitingExchange(t *testing.T) {
	queryReceived := make(chan struct{})
	releaseResponse := make(chan struct{})
	resolver := newFakeResolverFunc(t, func(msg *dns.Msg) *dns.Msg {
		close(queryReceived)
		<-releaseResponse
		return fixedResponse(dns.RcodeSuccess, nil)(msg)
	})
	t.Cleanup(func() { close(releaseResponse) })
	pool := testConnPool(t, resolver)
	active := exchangeWithPool(pool, context.Background())

	select {
	case <-queryReceived:
	case <-time.After(connPoolTestTimeout):
		t.Fatal("resolver did not receive the active exchange")
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	started := make(chan struct{})
	waiting := make(chan connPoolExchangeResult, 1)
	go func() {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(fakeHost), dns.TypeA)
		client := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
		close(started)
		response, _, err := pool.Exchange(ctx, client, msg)
		waiting <- connPoolExchangeResult{response: response, err: err}
	}()
	<-started
	pool.Close()

	require.ErrorIs(t, awaitPoolExchange(t, waiting).err, context.Canceled)
	require.Error(t, awaitPoolExchange(t, active).err)
	require.EqualValues(t, 1, resolver.Queries())
}

func TestConnPoolWaitingExchangeContextCancellation(t *testing.T) {
	queryReceived := make(chan struct{})
	releaseResponse := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseResponse) }) }
	resolver := newFakeResolverFunc(t, func(msg *dns.Msg) *dns.Msg {
		close(queryReceived)
		<-releaseResponse
		return fixedResponse(dns.RcodeSuccess, nil)(msg)
	})
	t.Cleanup(release)
	pool := testConnPool(t, resolver)
	active := exchangeWithPool(pool, context.Background())

	select {
	case <-queryReceived:
	case <-time.After(connPoolTestTimeout):
		t.Fatal("resolver did not receive the active exchange")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	t.Cleanup(cancel)
	result := awaitPoolExchange(t, exchangeWithPool(pool, ctx))
	require.ErrorIs(t, result.err, context.DeadlineExceeded)

	release()
	require.NoError(t, awaitPoolExchange(t, active).err)
}

func TestConnPoolRepeatedClose(t *testing.T) {
	resolver := newFakeResolver(t, dns.RcodeSuccess)
	pool := testConnPool(t, resolver)

	closed := make(chan struct{})
	go func() {
		pool.Close()
		pool.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(connPoolTestTimeout):
		t.Fatal("repeated pool close did not return")
	}
}

// TestNewWithOptionsPoolsOnlyUDPResolvers ensures NewWithOptions builds
// connection pools only for UDP resolvers, the only ones whose queries use
// them. It used to dial a DoH URL as a UDP address and fail.
func TestNewWithOptionsPoolsOnlyUDPResolvers(t *testing.T) {
	udp := newFakeResolver(t, dns.RcodeSuccess)
	doh := newFakeDoHResolver(t, dns.RcodeSuccess)
	client, err := NewWithOptions(Options{
		BaseResolvers: []string{
			udp.Addr(),
			"tcp:" + freeUDPAddr(t),
			"dot:" + freeUDPAddr(t),
			doh.ResolverString("post"),
		},
		MaxRetries:            1,
		ConnectionPoolThreads: 2,
	})
	require.NoError(t, err)
	t.Cleanup(client.Close)
	require.Len(t, client.udpConnPool.Map, 1)
	require.Contains(t, client.udpConnPool.Map, udp.Addr())
}
