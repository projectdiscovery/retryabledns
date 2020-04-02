package dns

import (
	"net"

	"github.com/miekg/dns"
)

// ReadResolveConfig reads the /etc/resolv.conf file to get the list
// of resolvers we can use for resolving DNS Names.
func ReadResolveConfig(configFile string) ([]string, error) {
	var servers []string

	conf, err := dns.ClientConfigFromFile(configFile)
	if err != nil {
		return servers, err
	}

	for _, nameserver := range conf.Servers {
		// If the resolvers have [] in front of them, fix that. Also, don't
		// get FQDN of such resolvers.
		if nameserver[0] == '[' && nameserver[len(nameserver)-1] == ']' {
			nameserver = nameserver[1 : len(nameserver)-1]
		}
		if ip := net.ParseIP(nameserver); ip != nil {
			nameserver = net.JoinHostPort(nameserver, defaultPort)
		} else {
			nameserver = dns.Fqdn(nameserver) + ":" + defaultPort
		}
		servers = append(servers, nameserver)
	}

	return servers, nil
}
