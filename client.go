package dns

import (
	"errors"
	"math/rand"
	"time"

	"github.com/miekg/dns"
)

const defaultPort = "53"

// Client is a DNS resolver client to resolve hostnames.
type Client struct {
	resolvers  []string
	maxRetries int
}

// Result contains the results from a DNS resolution
type Result struct {
	IPs []string
	TTL int
}

// New creates a new dns client
func New(baseResolvers []string, maxRetries int) (*Client, error) {
	// Seed the global RNG
	rand.Seed(time.Now().UnixNano())

	client := Client{maxRetries: maxRetries}

	// Attempt to retrieve the resolvers from the resolv.conf file on Linux/Unix
	// ignoring errors as it would return an empty list
	resolvers, _ := ReadResolveConfig("/etc/resolv.conf")
	client.resolvers = append(client.resolvers, resolvers...)

	// Append the static list of resolvers if they were given as input to the
	// resolvers array.
	client.resolvers = append(client.resolvers, baseResolvers...)

	return &client, nil
}

// Resolve is the underlying resolve function that actually resolves a host
// and gets the ip records for that host.
func (c *Client) Resolve(host string) (Result, error) {
	msg := new(dns.Msg)

	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{
		Name:   dns.Fqdn(host),
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}
	resolver := c.resolvers[rand.Intn(len(c.resolvers))]

	var err error
	var answer *dns.Msg

	result := Result{}

	for i := 0; i < c.maxRetries; i++ {
		answer, err = dns.Exchange(msg, resolver)
		if err != nil {
			continue
		}

		// In case we got some error from the server, return.
		if answer != nil && answer.Rcode != dns.RcodeSuccess {
			return result, errors.New(dns.RcodeToString[answer.Rcode])
		}

		for _, record := range answer.Answer {
			// Add the IP and the TTL to the map
			if t, ok := record.(*dns.A); ok {
				result.IPs = append(result.IPs, t.A.String())
				result.TTL = int(t.Header().Ttl)
			}
		}
		return result, nil
	}

	return result, err
}

// ResolveRaw is the underlying resolve function that actually resolves a host
// and gets the raw records for that host.
func (c *Client) ResolveRaw(host string, requestType uint16) (results []string, err error) {
	msg := new(dns.Msg)

	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = make([]dns.Question, 1)
	msg.Question[0] = dns.Question{
		Name:   dns.Fqdn(host),
		Qtype:  requestType,
		Qclass: dns.ClassINET,
	}
	resolver := c.resolvers[rand.Intn(len(c.resolvers))]

	var answer *dns.Msg

	for i := 0; i < c.maxRetries; i++ {
		answer, err = dns.Exchange(msg, resolver)
		if err != nil {
			continue
		}

		// In case we got some error from the server, return.
		if answer != nil && answer.Rcode != dns.RcodeSuccess {
			return results, errors.New(dns.RcodeToString[answer.Rcode])
		}

		results = append(results, parse(answer, requestType)...)

		return results, nil
	}

	return results, err
}

// Do sends a provided dns request and return the raw native response
func (c *Client) Do(msg *dns.Msg) (resp *dns.Msg, err error) {
	resolver := c.resolvers[rand.Intn(len(c.resolvers))]

	var answer *dns.Msg

	for i := 0; i < c.maxRetries; i++ {
		answer, err = dns.Exchange(msg, resolver)
		if err != nil {
			continue
		}

		// In case we get a non empty answer stop retrying
		if answer != nil {
			return answer, nil
		}
	}

	return nil, err
}

func parse(answer *dns.Msg, requestType uint16) (results []string) {
	for _, record := range answer.Answer {
		switch requestType {
		case dns.TypeA:
			if t, ok := record.(*dns.A); ok {
				results = append(results, t.String())
			}
		case dns.TypeNS:
			if t, ok := record.(*dns.NS); ok {
				results = append(results, t.String())
			}
		case dns.TypeCNAME:
			if t, ok := record.(*dns.CNAME); ok {
				results = append(results, t.String())
			}
		case dns.TypeSOA:
			if t, ok := record.(*dns.SOA); ok {
				results = append(results, t.String())
			}
		case dns.TypePTR:
			if t, ok := record.(*dns.PTR); ok {
				results = append(results, t.String())
			}
		case dns.TypeMX:
			if t, ok := record.(*dns.MX); ok {
				results = append(results, t.String())
			}
		case dns.TypeTXT:
			if t, ok := record.(*dns.TXT); ok {
				results = append(results, t.String())
			}
		case dns.TypeAAAA:
			if t, ok := record.(*dns.AAAA); ok {
				results = append(results, t.String())
			}
		}
	}

	return
}
