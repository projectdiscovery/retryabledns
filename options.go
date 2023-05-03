package retryabledns

import (
	"errors"
	"time"
)

var (
	ErrMaxRetriesZero = errors.New("retries must be at least 1")
	ErrResolversEmpty = errors.New("resolvers list must not be empty")
)

type Options struct {
	BaseResolvers []string
	MaxRetries    int
	Timeout       time.Duration
	Hostsfile     bool
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
