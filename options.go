package retryabledns

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var (
	ErrMaxRetriesZero  = errors.New("retries must be at least 1")
	ErrResolversEmpty  = errors.New("resolvers list must not be empty")
	ErrInvalidProtocol = errors.New("invalid protocol for local addr")
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

func (options *Options) SetLocalAddrIP(ip string) {
	ipStr := strings.TrimSpace(ip)
	if ipStr == "" {
		options.LocalAddrIP = nil
	}
	options.LocalAddrIP = net.ParseIP(ipStr)
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
