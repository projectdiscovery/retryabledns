package retryabledns

import (
	"errors"
	"time"
)

type Options struct {
	BaseResolvers []string
	MaxRetries    int
	Timeout       time.Duration
	Hostsfile     bool
}

func (options *Options) Validate() error {
	if options.MaxRetries == 0 {
		return errors.New("retries must be at least 1")
	}

	if len(options.BaseResolvers) == 0 {
		return errors.New("resolvers list must not be empty")
	}
	return nil
}
