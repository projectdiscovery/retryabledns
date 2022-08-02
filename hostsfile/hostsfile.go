package hostsfile

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/stringsutil"
)

const (
	localhostName = "localhost"
)

func Path() string {
	if isWindows() {
		return fmt.Sprintf(`%s\System32\Drivers\etc\hosts`, os.Getenv("SystemRoot"))
	}
	return "/etc/hosts"
}

func ParseDefault() (map[string][]string, error) {
	return Parse(Path())
}

func Parse(p string) (map[string][]string, error) {
	if !fileutil.FileExists(p) {
		return nil, errors.New("hosts file doesn't exist")
	}

	hostsFileCh, err := fileutil.ReadFile(p)
	if err != nil {
		return nil, err
	}

	items := make(map[string][]string)
	for line := range hostsFileCh {
		line = strings.TrimSpace(line)
		// skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// discard comment part
		if strings.Contains(line, "#") {
			line, err = stringsutil.Before(line, "#")
			if err != nil {
				return nil, err
			}
		}
		tokens := strings.Fields(line)
		if len(tokens) > 1 {
			ip := tokens[0]
			for _, hostname := range tokens[1:] {
				items[hostname] = append(items[hostname], ip)
			}
		}
	}

	// windows 11 resolves localhost with system dns resolver
	if _, ok := items[localhostName]; !ok && isWindows() {
		localhostIPs, err := net.LookupHost(localhostName)
		if err != nil {
			return nil, err
		}
		items[localhostName] = localhostIPs
	}

	return items, nil
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}
