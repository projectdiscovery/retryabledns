package retryabledns

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var (
	ErrMaxRetriesZero            = errors.New("retries must be at least 1")
	ErrResolversEmpty            = errors.New("resolvers list must not be empty")
	ErrInvalidProtocol           = errors.New("invalid protocol for local addr")
	ErrInvalidInterface          = errors.New("interface with name does not exist")
	ErrNoInterfaceAddressesFound = errors.New("interface has no available addresses to use")
)

type Options struct {
	BaseResolvers []string
	MaxRetries    int
	Timeout       time.Duration
	Hostsfile     bool
	LocalAddrIP   net.IP
	LocalAddrPort uint16
}

// Returns a net.Addr of a UDP or TCP type depending on whats required
func (options *Options) GetLocalAddr(proto Protocol) net.Addr {
	if options.LocalAddrIP == nil {
		return nil
	}
	ipPort := fmt.Sprintf("%s:%d", options.LocalAddrIP, options.LocalAddrPort)
	var ipAddr net.Addr
	switch proto {
	case UDP:
		ipAddr, _ = net.ResolveUDPAddr("udp", ipPort)
	default:
		ipAddr, _ = net.ResolveTCPAddr("tcp", ipPort)
	}
	return ipAddr
}

// Sets the ip from a string, if invalid sets as nil
func (options *Options) SetLocalAddrIP(ip string) {
	ipStr := strings.TrimSpace(ip)
	if ipStr == "" {
		options.LocalAddrIP = nil
	}
	options.LocalAddrIP = net.ParseIP(ipStr)
}

// Sets the first available IP from a network interface name e.g. eth0
func (options *Options) SetLocalAddrIPFromNetInterface(ifaceName string) error {
	if iface, err := net.InterfaceByName(ifaceName); iface != nil {
		if addrs, err := iface.Addrs(); len(addrs) > 0 {
			var foundAddr net.IP
		AddrLoop:
			// Loop through to find a valid address
			for _, addr := range addrs {
				addr := addr.(*net.IPNet)
				foundAddr = addr.IP
				break AddrLoop
			}
			if foundAddr != nil {
				options.LocalAddrIP = foundAddr
			} else {
				return ErrNoInterfaceAddressesFound
			}
		} else if len(addrs) == 0 {
			return ErrNoInterfaceAddressesFound
		} else if err != nil {
			return err
		}
	} else if err != nil {
		return ErrInvalidInterface
	}
	return nil
}

func (options *Options) Validate() error {
	if options.MaxRetries == 0 {
		return ErrMaxRetriesZero
	}

	if len(options.BaseResolvers) == 0 {
		return ErrResolversEmpty
	}
	return nil
}
