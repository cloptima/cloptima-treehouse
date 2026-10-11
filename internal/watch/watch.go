// Package watch triggers a callback shortly after a repo's working tree or
// .git refs change. Worktree synchronization and change debouncing run
// here, while notifications are computed server-side off snapshot timestamps,
// allowing the local debounce to stay short and cheap.
//
// macOS uses FSEvents (watch_darwin.go). Other platforms, and darwin builds
// without cgo, use fsnotify (watch_other.go).
package watch

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	syncDebounce = 3 * time.Second
	syncMaxWait  = 15 * time.Second
)

// debouncer calls fn once events stop arriving for syncDebounce, and at the
// latest syncMaxWait after the first event of a continuous burst.
type debouncer struct {
	fn func()

	mu           sync.Mutex
	timer        *time.Timer
	firstEventAt time.Time
	inFlight     bool
	pending      bool
}

// fire never drops a trigger: if fn is already running when it's called
// again, it marks the run as owed instead of returning silently, and the
// in-flight call loops to cover it before releasing inFlight.
func (d *debouncer) fire() {
	d.mu.Lock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.firstEventAt = time.Time{}
	if d.inFlight {
		d.pending = true
		d.mu.Unlock()
		return
	}
	d.inFlight = true
	d.mu.Unlock()

	for {
		d.fn()

		d.mu.Lock()
		if !d.pending {
			d.inFlight = false
			d.mu.Unlock()
			return
		}
		d.pending = false
		d.mu.Unlock()
	}
}

// reset records one event.
func (d *debouncer) reset() {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	if d.firstEventAt.IsZero() {
		d.firstEventAt = now
	}

	// If continuous events have spanned >= syncMaxWait, trigger immediately.
	if now.Sub(d.firstEventAt) >= syncMaxWait {
		if d.timer != nil {
			d.timer.Stop()
			d.timer = nil
		}
		d.firstEventAt = time.Time{}
		go d.fire()
		return
	}

	// Compute remaining budget before the max-wait ceiling is reached.
	delay := syncDebounce
	if remaining := syncMaxWait - now.Sub(d.firstEventAt); remaining < delay {
		delay = remaining
	}

	if d.timer == nil {
		d.timer = time.AfterFunc(delay, d.fire)
	} else {
		d.timer.Reset(delay)
	}
}

// stop cancels a pending call.
func (d *debouncer) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
}

// resolveGitDir reads a ".git" file's "gitdir: <path>" pointer (used by
// linked worktrees, where .git is a file rather than a directory) and
// returns the absolute git directory it points to.
func resolveGitDir(gitFilePath string) (string, error) {
	data, err := os.ReadFile(gitFilePath)
	if err != nil {
		return "", err
	}
	target, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir: ")
	if !ok || target == "" {
		return "", fmt.Errorf("unrecognized .git pointer file: %s", gitFilePath)
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(gitFilePath), target)
	}
	return filepath.Clean(target), nil
}

// commonDir reads a git directory's "commondir" file (present for a linked
// worktree's own gitdir, pointing back to the main repo's shared refs) and
// returns the absolute path it resolves to, or "" if there is none -- a
// main worktree's own .git directory has no commondir file.
func commonDir(gitDir string) string {
	data, err := os.ReadFile(filepath.Join(gitDir, "commondir"))
	if err != nil {
		return ""
	}
	target := strings.TrimSpace(string(data))
	if target == "" {
		return ""
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(gitDir, target)
	}
	return filepath.Clean(target)
}
