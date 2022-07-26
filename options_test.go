package retryabledns

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateOptions(t *testing.T) {
	options := Options{}
	err := options.Validate()
	require.NotNil(t, err)
}
