package kawaa

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every exported error type is one the client really returns. Until 0.2.0 the
// package declared AuthenticationError, RateLimitError,
// InsufficientCreditsError, ValidationError and NotFoundError, each documented
// as "returned when ...", yet nothing built them: errors.As on any of them never
// matched, while the client returned an *APIError to check with
// IsAuthenticationError() and its siblings.
func TestEveryExportedErrorTypeIsConstructed(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	declared := map[string]bool{}
	constructed := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.TypeSpec:
				if n.Name.IsExported() && strings.HasSuffix(n.Name.Name, "Error") {
					declared[n.Name.Name] = true
				}
			case *ast.CompositeLit:
				if ident, ok := n.Type.(*ast.Ident); ok {
					constructed[ident.Name] = true
				}
			}
			return true
		})
	}

	require.Contains(t, declared, "APIError")
	for name := range declared {
		assert.True(t, constructed[name], "%s is exported but the client never builds one", name)
	}
}
