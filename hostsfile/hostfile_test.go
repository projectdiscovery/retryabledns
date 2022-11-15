package hostsfile

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLinuxParsePassed(t *testing.T) {
	elem, err := Parse("../tests/linux_host")
	require.NotNil(t, elem, "host file empty")
	require.Nil(t, err, "an error was throwed, err var is not nil")
}

func TestMacosParsePassed(t *testing.T) {
	elem, err := Parse("../tests/macos_host")
	require.NotNil(t, elem, "host file empty")
	require.Nil(t, err, "an error was throwed, err var is not nil")
}

func TestWinParsePassed(t *testing.T) {
	elem, err := Parse("../tests/win_host")
	require.NotNil(t, elem, "host file empty")
	require.Nil(t, err, "an error was throwed, err var is not nil")
}
