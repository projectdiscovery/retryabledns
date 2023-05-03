package retryabledns

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
