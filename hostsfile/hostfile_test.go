package hostsfile

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Linux
func TestLinuxParsePassed(t *testing.T) {
	elem, err := Parse("./tests/linux_host")
	require.NotNil(t, elem, "host file empty")
	require.Nil(t, err, "an error was throwed, err var is not nil")
}

func TestLinuxParseTabSpacesComments(t *testing.T) {
	elem, err := Parse("./tests/linux_host_tabs_spaces_comments")
	require.NotNil(t, elem, "host file empty")
	require.Nil(t, err, "an error was throwed, err var is not nil")
}

func TestLinuxParseSpecialChars(t *testing.T) {
	elem, err := Parse("./tests/linux_host_special_chars")
	require.NotNil(t, elem, "host file empty")
	require.Nil(t, err, "an error was throwed, err var is not nil")
}

// Mac
func TestMacosParsePassed(t *testing.T) {
	elem, err := Parse("./tests/macos_host")
	require.NotNil(t, elem, "host file empty")
	require.Nil(t, err, "an error was throwed, err var is not nil")
}

func TestMacosParseTabSpacesComments(t *testing.T) {
	elem, err := Parse("./tests/macos_host_tabs_spaces_comments")
	require.NotNil(t, elem, "host file empty")
	require.Nil(t, err, "an error was throwed, err var is not nil")
}

func TestMacosParseSpecialChars(t *testing.T) {
	elem, err := Parse("./tests/macos_host_special_chars")
	require.NotNil(t, elem, "host file empty")
	require.Nil(t, err, "an error was throwed, err var is not nil")
}

// Windows
func TestWinParsePassed(t *testing.T) {
	elem, err := Parse("./tests/win_host")
	require.NotNil(t, elem, "host file empty")
	require.Nil(t, err, "an error was throwed, err var is not nil")
}

func TestWindowsParseTabSpacesComments(t *testing.T) {
	elem, err := Parse("./tests/win_host_tabs_spaces_comments")
	require.NotNil(t, elem, "host file empty")
	require.Nil(t, err, "an error was throwed, err var is not nil")
}

func TestWinParseSpecialChars(t *testing.T) {
	elem, err := Parse("./tests/win_host_special_chars")
	require.NotNil(t, elem, "host file empty")
	require.Nil(t, err, "an error was throwed, err var is not nil")
}
