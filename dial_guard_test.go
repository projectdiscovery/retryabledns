package retryabledns

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const thisPkg = "github.com/projectdiscovery/retryabledns"

// transportPkgs are the packages whose dial, exchange, listen and lookup
// functions reach a resolver without going through the proxy.
var transportPkgs = map[string]bool{
	"github.com/miekg/dns":   true,
	"crypto/tls":             true,
	"golang.org/x/net/proxy": true,
	"net":                    true,
}

// connectPrefixes start the names of functions that dial, exchange, listen or
// look up names.
var connectPrefixes = []string{"Dial", "Exchange", "Listen", "Lookup"}

// poolFuncs hand out pooled connections, which never go through the proxy.
var poolFuncs = map[string]bool{
	thisPkg + ".NewConnPool":               true,
	"(*" + thisPkg + ".ConnPool).Exchange": true,
}

// connectAllowed lists the only places that may use a connecting function:
// for each function in this package, the full names of the ones it may use.
// Everything else reaches resolvers through these functions, which is what
// keeps every connection on the proxy when Proxy is set.
var connectAllowed = map[string][]string{
	"Client.dial":               {"(*github.com/miekg/dns.Client).DialContext"},
	"Client.dialProxy":          {"(golang.org/x/net/proxy.ContextDialer).DialContext"},
	"Client.exchange":           {"(*github.com/miekg/dns.Client).ExchangeWithConn", "(*" + thisPkg + ".ConnPool).Exchange"},
	"Client.queryMultiple":      {"(*github.com/miekg/dns.Transfer).In"},      // its Conn comes from dial
	"Client.ResolveWithSyscall": {"net.LookupIP"},                             // the OS resolver, by design
	"Options.GetLocalAddr":      {"net.ResolveUDPAddr", "net.ResolveTCPAddr"}, // LocalAddrIP is an IP
	"NewWithOptions":            {thisPkg + ".NewConnPool"},                   // only without a proxy
	"NewConnPool":               {"github.com/miekg/dns.Dial"},
	"ConnPool.Exchange":         {"(*github.com/miekg/dns.Client).ExchangeWithConn"},
}

// TestResolverConnectionsGoThroughDial fails when code outside connectAllowed
// uses a function that talks to a resolver directly, which would bypass Proxy.
// It type-checks the package and matches the functions themselves, so calls,
// function values and dot imports are all caught. It also fails on allowlist
// entries that are no longer used, so the list can't keep a permission that a
// refactor made unnecessary. DoH is out of scope: query reaches DoH resolvers
// through dohClient, whose HTTP transport NewWithOptions builds with the proxy.
func TestResolverConnectionsGoThroughDial(t *testing.T) {
	fset, files, info := typeCheck(t)
	used := make(map[[2]string]bool) // owner, function
	for _, file := range files {
		for _, decl := range file.Decls {
			owner := "package level"
			if fn, ok := decl.(*ast.FuncDecl); ok {
				owner = funcName(fn)
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				fn, ok := info.Uses[id].(*types.Func)
				if !ok || !connects(fn) {
					return true
				}
				if slices.Contains(connectAllowed[owner], fn.FullName()) {
					used[[2]string{owner, fn.FullName()}] = true
				} else {
					t.Errorf("%s: %s uses %s directly; use query, exchange or dial so Proxy applies",
						fset.Position(id.Pos()), owner, fn.FullName())
				}
				return true
			})
		}
	}
	for owner, allowed := range connectAllowed {
		for _, name := range allowed {
			if !used[[2]string{owner, name}] {
				t.Errorf("connectAllowed lets %s use %s, but it no longer does; remove the entry", owner, name)
			}
		}
	}
}

// connects reports whether fn reaches a resolver without the proxy: a
// transport function that dials, exchanges, listens or resolves a name, a
// pool function, or a method with such a name on an interface declared here,
// which could wrap a dns.Client.
func connects(fn *types.Func) bool {
	if fn.Pkg() == nil {
		return false
	}
	switch path := fn.Pkg().Path(); {
	case path == thisPkg:
		recv := fn.Type().(*types.Signature).Recv()
		return poolFuncs[fn.FullName()] || connectingName(fn.Name()) && recv != nil && types.IsInterface(recv.Type())
	case transportPkgs[path]:
		return connectingName(fn.Name())
	}
	return false
}

// connectingName reports whether name is that of a function that dials,
// exchanges, listens or resolves a name. In is dns.Transfer.In, which dials by
// itself when the Transfer has no Conn.
func connectingName(name string) bool {
	return slices.ContainsFunc(connectPrefixes, func(prefix string) bool { return strings.HasPrefix(name, prefix) }) ||
		name == "In" || strings.HasPrefix(name, "Resolve") && strings.HasSuffix(name, "Addr")
}

// typeCheck parses and type-checks the files the build includes in this
// package, so files for other platforms are checked only on those platforms.
// Imports come from the export data that go list leaves in the build cache.
func typeCheck(t *testing.T) (*token.FileSet, []*ast.File, *types.Info) {
	t.Helper()
	var stderr bytes.Buffer
	cmd := exec.Command("go", "list", "-export", "-deps", "-json=ImportPath,Export,Dir,GoFiles,CgoFiles", ".")
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	require.NoError(t, err, "go list: %s", stderr.String())

	type listedPkg struct {
		ImportPath, Export, Dir string
		GoFiles, CgoFiles       []string
	}
	var self listedPkg
	exports := make(map[string]string)
	for dec := json.NewDecoder(bytes.NewReader(out)); dec.More(); {
		var p listedPkg
		require.NoError(t, dec.Decode(&p))
		exports[p.ImportPath] = p.Export
		if p.ImportPath == thisPkg {
			self = p
		}
	}

	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range slices.Concat(self.GoFiles, self.CgoFiles) {
		file, err := parser.ParseFile(fset, filepath.Join(self.Dir, name), nil, 0)
		require.NoError(t, err)
		files = append(files, file)
	}
	require.NotEmpty(t, files, "go list found no files for %s", thisPkg)

	info := &types.Info{Uses: make(map[*ast.Ident]types.Object)}
	conf := types.Config{
		Importer:    importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) { return os.Open(exports[path]) }),
		FakeImportC: true,
	}
	_, err = conf.Check(thisPkg, fset, files, info)
	require.NoError(t, err)
	return fset, files, info
}

// funcName returns fn's name, qualified by its receiver type for methods.
func funcName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	typ := fn.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	if ident, ok := typ.(*ast.Ident); ok {
		return ident.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}
