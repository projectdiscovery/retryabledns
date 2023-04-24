package main

import (
	"log"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/retryabledns"
)

func main() {
	options := retryabledns.Options{
		Hostsfile: true,
		BaseResolvers: []string{
			"1.1.1.1:53",
			"1.0.0.1:53",
			"8.8.8.8:53",
			"8.8.4.4:53",
		},
		MaxRetries: 5,
	}
	dnsClient, err := retryabledns.NewWithOptions(options)
	if err != nil {
		log.Fatal(err)
	}

	msg := &dns.Msg{}
	question := dns.Question{
		Name:   "hackeronezuppo.com",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}
	msg.Question = []dns.Question{question}

	for i := 0; i < 10; i++ {
		_, _ = dnsClient.Do(msg)
	}
}
