# Retryable dns resolver

Based on `miekg/dns` and freely inspired by `bogdanovich/dns_resolver`.

## Features

- Supports both system default DNS resolvers and user-provided ones
- Retries DNS requests in case of I/O errors, timeouts, or network failures
- Allows arbitrary query types
- Resolution with random resolvers
- Compatible with various DNS resolver protocols (TCP, UDP, DoH, and DoT)
- Per-resolver stats (requests, errors, latency)

### Using *go get*

```console
$ go get github.com/projectdiscovery/retryabledns
```

After this command *retryabledns* library source will be in your $GOPATH

## `/etc/hosts` file processing

By default, the library processes the `/etc/hosts` file up to a maximum amount of lines for efficiency (4096). If your setup has a larger hosts file and you want to process more lines, you can easily configure this limit by adjusting the `hostsfile.MaxLines` variable.

For example:

``` go
hostsfile.MaxLines = 10000  // Now the library will process up to 10000 lines from the hosts file
```

## Example

Usage Example:

``` go
package main

import (
    "log"

    "github.com/projectdiscovery/retryabledns"
    "github.com/miekg/dns"
)

func main() {
    // It requires a list of resolvers.
    // Valid protocols are "udp", "tcp", "doh", "dot". Default are "udp".
    resolvers := []string{"8.8.8.8:53", "8.8.4.4:53", "tcp:1.1.1.1"}
    retries := 2
    hostname := "hackerone.com"

    dnsClient, err := retryabledns.New(resolvers, retries)
    if err != nil {
        log.Fatal(err)
    }

    ips, err := dnsClient.Resolve(hostname)
    if err != nil {
        log.Fatal(err)
    }

    log.Println(ips)

    // Query Types: dns.TypeA, dns.TypeNS, dns.TypeCNAME, dns.TypeSOA, dns.TypePTR, dns.TypeMX, dns.TypeANY
    // dns.TypeTXT, dns.TypeAAAA, dns.TypeSRV (from github.com/miekg/dns)
    // retryabledns.ErrRetriesExceeded will be returned if a result isn't returned in max retries
    dnsResponses, err := dnsClient.Query(hostname, dns.TypeA)
    if err != nil {
        log.Fatal(err)
    }

    log.Println(dnsResponses)
}
```

## Per-resolver stats

Every client automatically tracks per-resolver counters (requests, successes, errors, total/average/last round-trip, last error). Read them at any time with `Client.Stats()` and clear with `Client.ResetStats()`.

```go
stats := dnsClient.Stats()
for resolver, s := range stats {
    log.Printf("%s: %d req (%d ok, %d err), avg=%s last_err=%v",
        resolver, s.Requests, s.Successes, s.Errors, s.AverageDuration, s.LastError)
}
```

Stats are updated lock-free on the hot path and are safe to read concurrently. The snapshot returned by `Stats()` is fully owned by the caller.

Credits:

- `https://github.com/lixiangzhong/dnsutil`
- `https://github.com/rs/dnstrace`
