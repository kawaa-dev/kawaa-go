package kawaa

import (
	"os"
	"path/filepath"
)

// sharedFixture returns the path of a test fixture that every Kawaa SDK shares:
// testdata/ when this directory has one, ../testdata/ otherwise.
func sharedFixture(parts ...string) string {
	root := "testdata"
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		root = filepath.Join("..", "testdata")
	}
	return filepath.Join(append([]string{root}, parts...)...)
}
