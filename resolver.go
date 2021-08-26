package retryabledns

import (
	"net"
	"strings"

	"github.com/projectdiscovery/stringsutil"
)

type Protocol int

const (
	UDP Protocol = iota
	TCP
)

func (p Protocol) String() string {
	if p == UDP {
		return "udp"
	}
	return "tcp"
}

type Resolver struct {
	Protocol Protocol
	Host     string
	Port     string
}

func (r Resolver) String() string {
	return net.JoinHostPort(r.Host, r.Port)
}

func parseResolver(r string) Resolver {
	var resolver Resolver
	resolver.Protocol = UDP
	if strings.HasPrefix(r, TCP.String()+":") {
		resolver.Protocol = TCP
	}
	r = stringsutil.TrimPrefixAny(r, TCP.String()+":", UDP.String()+":")
	if host, port, err := net.SplitHostPort(r); err == nil {
		resolver.Host = host
		resolver.Port = port
	} else {
		resolver.Host = r
		resolver.Port = "53"
	}
	return resolver
}

func parseResolvers(resolvers []string) []Resolver {
	var parsedResolvers []Resolver
	for _, resolver := range resolvers {
		parsedResolvers = append(parsedResolvers, parseResolver(resolver))
	}
	return parsedResolvers
}
