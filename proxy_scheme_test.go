package retryabledns

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateProxyScheme(t *testing.T) {
	newOptions := func(proxy string) Options {
		return Options{
			BaseResolvers: []string{"127.0.0.1:53"},
			MaxRetries:    1,
			Proxy:         proxy,
		}
	}

	rejected := []struct {
		name   string
		proxy  string
		scheme string // as it must appear in the error message
	}{
		{"http", "http://127.0.0.1:8080", "http"},
		{"http with credentials", "http://user:pass@127.0.0.1:8080", "http"},
		{"https", "https://127.0.0.1:8443", "https"},
		{"socks4", "socks4://127.0.0.1:1080", "socks4"},
		{"no scheme", "127.0.0.1", ""},
		{"empty scheme", "//127.0.0.1:1080", ""},
	}
	for _, tc := range rejected {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			options := newOptions(tc.proxy)
			want := fmt.Sprintf("%q", tc.scheme)

			err := options.Validate()
			require.ErrorIs(t, err, ErrProxySchemeUnsupported)
			require.ErrorContains(t, err, want)
			require.ErrorContains(t, err, "socks5")

			client, err := NewWithOptions(options)
			require.ErrorIs(t, err, ErrProxySchemeUnsupported)
			require.ErrorContains(t, err, want)
			require.Nil(t, client)
		})
	}

	t.Run("rejects unparsable proxy URL", func(t *testing.T) {
		options := newOptions("socks5://user:secret@127.0.0.1:bad")
		err := options.Validate()
		require.ErrorContains(t, err, "invalid proxy URL")
		require.NotErrorIs(t, err, ErrProxySchemeUnsupported)
		require.NotContains(t, err.Error(), "secret")

		client, err := NewWithOptions(options)
		require.ErrorContains(t, err, "invalid proxy URL")
		require.Nil(t, client)
	})

	accepted := []struct {
		name  string
		proxy string
	}{
		{"empty", ""},
		{"socks5", "socks5://127.0.0.1:1080"},
		{"socks5h", "socks5h://127.0.0.1:1080"},
		{"socks5 with credentials", "socks5://user:pass@127.0.0.1:1080"},
		{"socks5h with credentials", "socks5h://user:pass@127.0.0.1:1080"},
		{"uppercase scheme", "SOCKS5://127.0.0.1:1080"},
	}
	for _, tc := range accepted {
		t.Run("accepts "+tc.name, func(t *testing.T) {
			options := newOptions(tc.proxy)
			require.NoError(t, options.Validate())

			client, err := NewWithOptions(options)
			require.NoError(t, err)
			require.NotNil(t, client)
		})
	}
}
