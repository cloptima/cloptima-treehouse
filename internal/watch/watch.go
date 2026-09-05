// Package watch triggers a callback shortly after a repo's working tree or
// .git refs change. Worktree synchronization and change debouncing run
// here, while notifications are computed server-side off snapshot timestamps,
// allowing the local debounce to stay short and cheap.
package watch

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	syncDebounce = 3 * time.Second
	syncMaxWait  = 15 * time.Second
)

// Watcher watches one repo root (fsnotify has no native recursive mode) and
// calls onChange, debounced, whenever anything under it changes.
type Watcher struct {
	repoPath string
	onChange func()
	fsw      *fsnotify.Watcher
}

func New(repoPath string, onChange func()) (*Watcher, error) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	w := &Watcher{repoPath: repoPath, onChange: onChange, fsw: fsw}
	if err := w.addWatches(repoPath); err != nil {
		fsw.Close()
		return nil, err
	}
	return w, nil
}

// addWatches walks root and registers every directory under it that is worth
// watching.
//
// The "is this the top of the tree" tests below compare against w.repoPath,
// the worktree root, and deliberately not against this call's own root. Run
// once from New that distinction does not exist, but addWatches is also
// called for each directory created while the daemon is running (see Run) --
// and there the walk root IS the new directory. Comparing against the walk
// root there made every exclusion vacuous for exactly the case it exists to
// stop: a `node_modules` created by `npm install` became its own root, so
// `path != root` was false at its top level and the whole tree was watched.
// On darwin fsnotify is kqueue-backed and holds one file descriptor per
// watched path, so that is tens of thousands of descriptors plus a
// continuous debounce storm from a single install.
func (w *Watcher) addWatches(root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // best-effort: a permission error on one dir shouldn't abort the whole watch
		}
		name := d.Name()
		if path != w.repoPath && name == ".git" {
			if d.IsDir() {
				// Only branch/HEAD/staging changes matter for a live status
				// view, not the (huge, high-churn) object store.
				w.watchGitDir(path)
				return filepath.SkipDir
			}
			// A linked worktree's ".git" is a pointer file ("gitdir: ..."),
			// not a directory. d.IsDir() is false for it, so without this
			// branch it would just fall through the generic file-skip below
			// and this worktree's branch/staging state would never be
			// watched at all -- only its ordinary working-tree file edits
			// would trigger a sync, never a `git commit`/`checkout`/`add`.
			if gitDir, resolveErr := resolveGitDir(path); resolveErr == nil {
				w.watchGitDir(gitDir)
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		// Deferring to `git check-ignore` rather than a hardcoded directory
		// name list: every ecosystem has its own build/cache/dependency
		// directories (node_modules, vendor, a Python venv, this repo's own
		// .tmp-go-cache), the set is unbounded, and a hardcoded list only
		// ever covers what someone happened to hit before. .gitignore
		// already answers "does this repo consider this path noise" --
		// including nested .gitignore files, .git/info/exclude, and the
		// user's global excludesfile -- so this asks git instead of
		// maintaining a second, always-incomplete copy of that answer.
		if path != w.repoPath && isGitIgnored(w.repoPath, path) {
			return filepath.SkipDir
		}
		if err := w.fsw.Add(path); err != nil {
			// Best-effort, matching the WalkDir-error case above: a single
			// unwatchable path (a dangling symlink inside a venv, a
			// permissions error, a TOCTOU race with something deleting the
			// directory mid-walk) must not take down watching for every
			// other directory in the repo.
			log.Printf("treehouse: failed to watch %s: %v", path, err)
		}
		return nil
	})
}

// isGitIgnored reports whether git itself would ignore path -- checked with
// `git check-ignore` rather than reimplemented, since gitignore's pattern
// language (negation, anchoring, **, directory-only rules, precedence across
// nested files) is exactly what git already gets right. One subprocess per
// directory encountered during a walk is a one-time cost at watcher startup
// (or, rarely, when a new top-level directory appears mid-run), not a
// per-sync cost, so correctness wins over micro-optimizing it away.
func isGitIgnored(repoPath, path string) bool {
	cmd := exec.Command("git", "check-ignore", "-q", path)
	cmd.Dir = repoPath
	return cmd.Run() == nil
}

// watchGitDir watches one git directory's HEAD (branch checkout) and index
// (staging area) -- the two files a live status view actually needs beyond
// refs -- plus its refs, wherever they actually live. A linked worktree's
// own gitdir (resolved via resolveGitDir) has no refs of its own; those are
// shared through its commondir pointer back to the main repo.
func (w *Watcher) watchGitDir(gitDir string) {
	_ = w.fsw.Add(filepath.Join(gitDir, "HEAD"))
	_ = w.fsw.Add(filepath.Join(gitDir, "index"))
	refsDir := gitDir
	if common := commonDir(gitDir); common != "" {
		refsDir = common
	}
	w.addRefsWatches(filepath.Join(refsDir, "refs"))
}

// addRefsWatches watches every directory under a git refs/ tree
// unconditionally. It deliberately does not reuse addWatches: git itself
// reports every path under .git (refs included) as ignored -- there is
// nothing to check, `.git` was never part of the trackable working tree to
// begin with -- so running addWatches's isGitIgnored check here would skip
// refs/ entirely on every single repo. refs/ also never contains a nested
// worktree, so none of addWatches's ".git" pointer-file handling applies
// either; this is intentionally the minimal walk refs/ actually needs.
func (w *Watcher) addRefsWatches(root string) {
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // best-effort, same as addWatches
		}
		if !d.IsDir() {
			return nil
		}
		if err := w.fsw.Add(path); err != nil {
			log.Printf("treehouse: failed to watch %s: %v", path, err)
		}
		return nil
	})
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

// WatchedPaths returns the filesystem paths this watcher currently tracks.
// Production code has no need to introspect this; it exists for tests.
func (w *Watcher) WatchedPaths() []string {
	return w.fsw.WatchList()
}

// Close stops the watcher immediately, independent of the shared stop
// channel passed to Run -- used to drop a single worktree's watcher (e.g.
// `git worktree remove`) without tearing down every other watcher sharing
// that channel. Run's own event loop sees the resulting closed Events
// channel and returns on its own, so this never races a later Run(stop)
// exit into closing fsw twice.
func (w *Watcher) Close() error {
	return w.fsw.Close()
}

// Run blocks, invoking onChange (debounced with a max-wait ceiling) until stop is closed.
func (w *Watcher) Run(stop <-chan struct{}) {
	var (
		mu           sync.Mutex
		timer        *time.Timer
		firstEventAt time.Time
		inFlight     bool
		pending      bool
	)

	// fire never drops a trigger: if onChange is already running when it's
	// called again, it marks the run as owed instead of returning silently,
	// and the in-flight call loops to cover it before releasing inFlight.
	fire := func() {
		mu.Lock()
		if timer != nil {
			timer.Stop()
			timer = nil
		}
		firstEventAt = time.Time{}
		if inFlight {
			pending = true
			mu.Unlock()
			return
		}
		inFlight = true
		mu.Unlock()

		for {
			w.onChange()

			mu.Lock()
			if !pending {
				inFlight = false
				mu.Unlock()
				return
			}
			pending = false
			mu.Unlock()
		}
	}

	reset := func() {
		mu.Lock()
		defer mu.Unlock()

		now := time.Now()
		if firstEventAt.IsZero() {
			firstEventAt = now
		}

		// If continuous events have spanned >= syncMaxWait, trigger immediately.
		if now.Sub(firstEventAt) >= syncMaxWait {
			if timer != nil {
				timer.Stop()
				timer = nil
			}
			firstEventAt = time.Time{}
			go fire()
			return
		}

		// Compute remaining budget before the max-wait ceiling is reached.
		delay := syncDebounce
		if remaining := syncMaxWait - now.Sub(firstEventAt); remaining < delay {
			delay = remaining
		}

		if timer == nil {
			timer = time.AfterFunc(delay, fire)
		} else {
			timer.Reset(delay)
		}
	}

	for {
		select {
		case <-stop:
			mu.Lock()
			if timer != nil {
				timer.Stop()
				timer = nil
			}
			mu.Unlock()
			w.fsw.Close()
			return
		case event, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Create != 0 {
				if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
					if err := w.addWatches(event.Name); err != nil {
						log.Printf("treehouse: failed to watch new directory %s: %v", event.Name, err)
					}
				}
			}
			reset()
		case err, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			log.Printf("treehouse: watch error for %s: %v", w.repoPath, err)
		}
	}
}
