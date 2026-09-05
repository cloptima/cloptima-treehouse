//go:build darwin && cgo && !notray

package tray

import (
	"strings"
	"testing"
)

// Which install method a user chose is inferred entirely from this path
// check, so it is worth pinning against the layouts each one actually
// produces: getting it wrong either hangs the formula install in an
// invisible event loop or drops the menu bar from the cask install.
func TestIsBundledPathDistinguishesInstallLayouts(t *testing.T) {
	bundled := []string{
		"/Applications/Treehouse.app/Contents/MacOS/treehouse",
		"/Users/dev/Downloads/Treehouse.app/Contents/MacOS/treehouse",
		"/opt/homebrew/Caskroom/treehouse/0.1.0/Treehouse.app/Contents/MacOS/treehouse",
	}
	for _, path := range bundled {
		if !isBundledPath(path) {
			t.Errorf("expected a bundled layout for %s", path)
		}
	}

	bare := []string{
		// What the Homebrew formula installs, and what its symlink resolves to.
		"/opt/homebrew/bin/treehouse",
		"/opt/homebrew/Cellar/treehouse-cli/0.1.0/bin/treehouse",
		"/usr/local/bin/treehouse",
		"/Users/dev/go/bin/treehouse",
		// A directory merely named like a bundle is not one: the executable
		// has to sit behind Contents/MacOS.
		"/Users/dev/Treehouse.app/treehouse",
		"/Users/dev/src/treehouse.appdata/treehouse",
	}
	for _, path := range bare {
		if isBundledPath(path) {
			t.Errorf("expected a bare layout for %s", path)
		}
	}
}

// The notice is what a formula user sees instead of an icon, so it has to
// name the install that would give them one.
func TestUnavailableNoticePointsAtTheCask(t *testing.T) {
	notice := UnavailableNotice()
	for _, want := range []string{"headless", "--cask", "cloptima/tap/treehouse"} {
		if !strings.Contains(notice, want) {
			t.Fatalf("notice must mention %q, got: %s", want, notice)
		}
	}
}
