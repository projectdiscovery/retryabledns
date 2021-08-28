package doh

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestConsistentResolve(t *testing.T) {
	client := New()
	var lastAnswer string
	for i := 0; i < 10; i++ {
		d, err := client.Query("example.com", A)
		require.Nil(t, err, "could not resolve dns")
		if lastAnswer == "" {
			lastAnswer = d.Answer[0].Data
		} else {
			require.Equal(t, lastAnswer, d.Answer[0].Data, "got another data from previous")
		}
	}
}

func TestResolvers(t *testing.T) {
	client := New()
	d, err := client.QueryWithDOH(MethodGet, OpenDNS, "www.example.com", dns.TypeA)
	require.Nil(t, err, "could not resolve dns")
	require.NotNil(t, d, "could not retrieve data")
	d, err = client.QueryWithDOH(MethodPost, OpenDNS, "www.example.com", dns.TypeA)
	require.Nil(t, err, "could not resolve dns")
	require.NotNil(t, d, "could not retrieve data")
}
