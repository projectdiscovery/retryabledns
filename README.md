# Retryable dns resolver
Based on based on miekg/dns and freely inspired by https://github.com/bogdanovich/dns_resolver.

## Features
- Supports system default resolvers along with user supplied ones
- Retries dns requests in case of I/O/Time/Network failures
- Allows arbitrary query types
- Resolution with random resolvers

### Using *go get*

```
$ go get github.com/projectdiscovery/retryabledns
```

After this command *retryabledns* is ready to use as the source will be in your $GOPATH

## Example
Usage Example:

``` go
package main

import (
    "log"
    "github.com/projectdiscovery/retryabledns"
)

func main() {
    // it requires a list of resolvers
    resolvers := []string{"8.8.8.8", "8.8.4.4"}
    retries := 2
    hostname := "hackerone.com"
    dnsClient, err := dns.New(resolvers, retries)
    if err != nil {
        return nil, err
    }

    ips, err := d.dnsClient.Resolve(hostname)
    if err != nil {
        log.Fatal(err)
    }

    log.Println(ips)

    // Query Types: dns.TypeA, dns.TypeNS, dns.TypeCNAME, dns.TypeSOA, dns.TypePTR, dns.TypeMX
    // dns.TypeTXT, dns.TypeAAAA (from github.com/miekg/dns)
    dnsResponses, err := d.dnsClient.ResolveRaw(hostname, dns.TypeA)
    if err != nil {
        log.Fatal(err)
    }

    log.Println(dnsResponses)
}
```