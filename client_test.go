package retryabledns

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConsistentResolve(t *testing.T) {
	client := New([]string{"8.8.8.8:53", "1.1.1.1:53"}, 5)

	var last string
	for i := 0; i < 10; i++ {
		d, err := client.Resolve("example.com")
		require.Nil(t, err, "could not resolve dns")

		if last != "" {
			require.Equal(t, last, d.A[0], "got another data from previous")
		} else {
			last = d.A[0]
		}
	}
}
