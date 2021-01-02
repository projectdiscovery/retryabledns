package retryabledns

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

// Client is a DNS resolver client to resolve hostnames.
type Client struct {
	resolvers    []string
	maxRetries   int
	serversIndex uint32
}

const defaultPort = "53"

// New creates a new dns client
func New(baseResolvers []string, maxRetries int) *Client {
	client := Client{
		maxRetries: maxRetries,
		resolvers:  baseResolvers,
	}
	return &client
}

// Resolve is the underlying resolve function that actually resolves a host
// and gets the ip records for that host.
func (c *Client) Resolve(host string) (*DNSData, error) {
	return c.Query(host, dns.TypeA)
}

// Do sends a provided dns request and return the raw native response
func (c *Client) Do(msg *dns.Msg) (*dns.Msg, error) {
	for i := 0; i < c.maxRetries; i++ {
		index := atomic.AddUint32(&c.serversIndex, 1)
		resolver := c.resolvers[index%uint32(len(c.resolvers))]

		resp, err := dns.Exchange(msg, resolver)
		if err != nil || resp == nil {
			continue
		}

		if resp.Rcode != dns.RcodeSuccess {
			continue
		}
		// In case we get a non empty answer stop retrying
		return resp, nil
	}
	return nil, errors.New("could not resolve, max retries exceeded")
}

// Query sends a provided dns request and return enriched response
func (c *Client) Query(host string, requestType uint16) (*DNSData, error) {
	return c.QueryMultiple(host, []uint16{requestType})
}

// QueryMultiple sends a provided dns request and return the data
func (c *Client) QueryMultiple(host string, requestTypes []uint16) (*DNSData, error) {
	var (
		dnsdata DNSData
		err     error
	)

	msg := dns.Msg{}
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = make([]dns.Question, 1)

	for _, requestType := range requestTypes {
		name := dns.Fqdn(host)

		// In case of PTR adjust the domain name
		if requestType == dns.TypePTR {
			var err error
			if net.ParseIP(host) != nil {
				name, err = dns.ReverseAddr(host)
				if err != nil {
					return nil, err
				}
			}
			msg.SetEdns0(4096, false)
		}

		question := dns.Question{
			Name:   name,
			Qtype:  requestType,
			Qclass: dns.ClassINET,
		}
		msg.Question[0] = question

		var resp *dns.Msg
		for i := 0; i < c.maxRetries; i++ {
			index := atomic.AddUint32(&c.serversIndex, 1)
			resolver := c.resolvers[index%uint32(len(c.resolvers))]

			resp, err = dns.Exchange(&msg, resolver)
			if err != nil || resp == nil {
				continue
			}
			// In case we got some error from the server, return.
			if resp.Rcode != dns.RcodeSuccess {
				continue
			}

			dnsdata.ParseFromMsg(resp)
			if !dnsdata.contains() {
				continue
			}
			dnsdata.Host = host
			dnsdata.Raw += resp.String()
			dnsdata.StatusCode = dns.RcodeToString[resp.Rcode]
			dnsdata.Resolver = append(dnsdata.Resolver, resolver)
			dnsdata.dedupe()
			return &dnsdata, err
		}
	}
	return nil, err
}

// DNSData is the data for a DNS request response
type DNSData struct {
	Host       string   `json:"host,omitempty"`
	TTL        int      `json:"ttl,omitempty"`
	Resolver   []string `json:"resolver,omitempty"`
	A          []string `json:"a,omitempty"`
	AAAA       []string `json:"aaaa,omitempty"`
	CNAME      []string `json:"cname,omitempty"`
	MX         []string `json:"mx,omitempty"`
	PTR        []string `json:"ptr,omitempty"`
	SOA        []string `json:"soa,omitempty"`
	NS         []string `json:"ns,omitempty"`
	TXT        []string `json:"txt,omitempty"`
	Raw        string   `json:"raw,omitempty"`
	StatusCode string   `json:"status_code,omitempty"`
}

// ParseFromMsg and enrich data
func (d *DNSData) ParseFromMsg(msg *dns.Msg) error {
	for _, record := range msg.Answer {
		switch record.(type) {
		case *dns.A:
			d.A = append(d.A, trimChars(record.(*dns.A).A.String()))
		case *dns.NS:
			d.NS = append(d.NS, trimChars(record.(*dns.NS).Ns))
		case *dns.CNAME:
			d.CNAME = append(d.CNAME, trimChars(record.(*dns.CNAME).Target))
		case *dns.SOA:
			d.SOA = append(d.SOA, trimChars(record.(*dns.SOA).Mbox))
		case *dns.PTR:
			d.PTR = append(d.PTR, trimChars(record.(*dns.PTR).Ptr))
		case *dns.MX:
			d.MX = append(d.MX, trimChars(record.(*dns.MX).Mx))
		case *dns.TXT:
			for _, txt := range record.(*dns.TXT).Txt {
				d.TXT = append(d.TXT, trimChars(txt))
			}
		case *dns.AAAA:
			d.AAAA = append(d.AAAA, trimChars(record.(*dns.AAAA).AAAA.String()))
		}
	}
	return nil
}

func (d *DNSData) contains() bool {
	if len(d.A) > 0 || len(d.AAAA) > 0 || len(d.CNAME) > 0 || len(d.MX) > 0 || len(d.NS) > 0 || len(d.PTR) > 0 || len(d.TXT) > 0 {
		return true
	}
	return false
}

// JSON returns the object as json string
func (d *DNSData) JSON() (string, error) {
	b, err := json.Marshal(&d)
	return string(b), err
}

func trimChars(s string) string {
	return strings.TrimRight(s, ".")
}

func (d *DNSData) dedupe() {
	d.Resolver = deduplicate(d.Resolver)
	d.A = deduplicate(d.A)
	d.AAAA = deduplicate(d.AAAA)
	d.CNAME = deduplicate(d.CNAME)
	d.MX = deduplicate(d.MX)
	d.PTR = deduplicate(d.PTR)
	d.SOA = deduplicate(d.SOA)
	d.NS = deduplicate(d.NS)
	d.TXT = deduplicate(d.TXT)
}

// Marshal encodes the dnsdata to a binary representation
func (d *DNSData) Marshal() ([]byte, error) {
	var b bytes.Buffer
	enc := gob.NewEncoder(&b)
	err := enc.Encode(d)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Unmarshal decodes the dnsdata from a binary representation
func (d *DNSData) Unmarshal(b []byte) error {
	dec := gob.NewDecoder(bytes.NewBuffer(b))
	err := dec.Decode(&d)
	return err
}

// deduplicate returns a new slice with duplicates values removed.
func deduplicate(s []string) []string {
	if len(s) < 2 {
		return s
	}
	var results []string
	seen := make(map[string]struct{})
	for _, val := range s {
		if _, ok := seen[val]; !ok {
			results = append(results, val)
			seen[val] = struct{}{}
		}
	}
	return results
}
