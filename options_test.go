package retryabledns

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetLocalAddrIPFromNetInterface(t *testing.T) {
	options := Options{
		MaxRetries: 0,
	}
	err := options.SetLocalAddrIPFromNetInterface("lo0")
	require.Nil(t, err)
	require.NotNil(t, options.LocalAddrIP)
	require.Equal(t, "127.0.0.1", options.LocalAddrIP.String())

	/** Should error with invalid interface name **/
	err = options.SetLocalAddrIPFromNetInterface("lo1234")
	require.NotNil(t, err)
}

func TestValidateOptions(t *testing.T) {
	t.Run("empty options", func(t *testing.T) {
		options := Options{}
		err := options.Validate()
		require.NotNil(t, err)
	})

	t.Run("max retries errors with zero", func(t *testing.T) {
		options := Options{
			MaxRetries: 0,
		}
		err := options.Validate()
		require.ErrorIs(t, err, ErrMaxRetriesZero)
	})

	t.Run("base resolvers errors if empty", func(t *testing.T) {
		options := Options{
			MaxRetries:    1,
			BaseResolvers: []string{},
		}
		err := options.Validate()
		require.ErrorIs(t, err, ErrResolversEmpty)
	})
}
