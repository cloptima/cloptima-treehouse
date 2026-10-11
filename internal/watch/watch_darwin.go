//go:build darwin && cgo

package watch

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsevents"
)

// fseventsLatency is how long FSEvents coalesces changes before it wakes the
// daemon. It is well under syncDebounce, so no sync waits noticeably longer.
const fseventsLatency = time.Second

// eventsBuffer lets a callback still running when Close stops the stream
// hand over its batch without blocking. See Close.
const eventsBuffer = 4

// droppedEvents marks a batch in which FSEvents lost events. Something
// changed, and there is no path to check.
const droppedEvents = fsevents.MustScanSubDirs | fsevents.UserDropped | fsevents.KernelDropped

// Watcher watches one worktree through one recursive FSEvents stream.
//
// fsnotify uses kqueue on darwin, which holds an open descriptor for every
// watched file and directory. A large worktree cost tens of thousands of
// descriptors, every git subprocess inherited the whole table, and a deleted
// tree kept its descriptors until restart. FSEvents holds none.
//
// FSEvents also reports ignored paths, so the gitignore check runs when a
// debounced burst flushes: one `git check-ignore` for the whole burst, and
// only when the burst touched working-tree paths alone.
type Watcher struct {
	root     string // worktree root with symlinks resolved, as FSEvents reports it
	gitDir   string // this worktree's git dir, for HEAD and index
	refsDir  string // refs, shared through commondir for a linked worktree
	onChange func()
	stream   *fsevents.EventStream
	debounce *debouncer

	mu    sync.Mutex
	dirty bool                // git state changed or events were dropped
	paths map[string]struct{} // working-tree paths changed since the last flush, relative to root

	closed    chan struct{} // closed by Close, under mu
	pumpDone  chan struct{}
	closeOnce sync.Once
}

func New(repoPath string, onChange func()) (*Watcher, error) {
	root, err := filepath.EvalSymlinks(repoPath)
	if err != nil {
		return nil, err
	}
	w := &Watcher{
		root:     root,
		onChange: onChange,
		paths:    map[string]struct{}{},
		closed:   make(chan struct{}),
		pumpDone: make(chan struct{}),
	}
	w.debounce = &debouncer{fn: w.flush}

	streamPaths := []string{root}
	if gitDir := gitDirOf(root); gitDir != "" {
		refsBase := gitDir
		if common := commonDir(gitDir); common != "" {
			refsBase = common
		}
		w.gitDir = realPath(gitDir)
		w.refsDir = realPath(filepath.Join(refsBase, "refs"))
		// A linked worktree's git dir and refs live in the main repo's
		// .git, outside its root.
		for _, p := range []string{w.gitDir, w.refsDir} {
			if _, inside := relWithin(root, p); !inside {
				streamPaths = append(streamPaths, p)
			}
		}
	}

	w.stream = &fsevents.EventStream{
		Events:  make(chan []fsevents.Event, eventsBuffer),
		Paths:   streamPaths,
		Latency: fseventsLatency,
		Flags:   fsevents.FileEvents,
	}
	if err := w.stream.Start(); err != nil {
		return nil, err
	}
	go w.pump()
	return w, nil
}

// gitDirOf returns root's git dir: .git itself, or the target of a linked
// worktree's .git pointer file. It returns "" when root has neither.
func gitDirOf(root string) string {
	dotGit := filepath.Join(root, ".git")
	info, err := os.Stat(dotGit)
	if err != nil {
		return ""
	}
	if info.IsDir() {
		return dotGit
	}
	gitDir, err := resolveGitDir(dotGit)
	if err != nil {
		return ""
	}
	return gitDir
}

func realPath(path string) string {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		return real
	}
	return path
}

// relWithin reports whether path is base or under it, and its path relative
// to base ("" for base itself). The match ignores case. macOS volumes are
// case-insensitive by default, FSEvents reports the case on disk, and a
// worktree path from `git worktree list` keeps the case it was typed with.
// A case mismatch made every event fall through to an unconditional sync.
func relWithin(base, path string) (string, bool) {
	if len(path) < len(base) || !strings.EqualFold(path[:len(base)], base) {
		return "", false
	}
	if len(path) == len(base) {
		return "", true
	}
	if path[len(base)] != '/' {
		return "", false
	}
	return path[len(base)+1:], true
}

type eventKind int

const (
	// ignoreEvent is git internals a status view never reads, such as the
	// object store.
	ignoreEvent eventKind = iota
	// gitStateEvent is HEAD, the index, or a ref. It syncs without a check.
	gitStateEvent
	// workTreeEvent is a working-tree path. It syncs unless git ignores it.
	workTreeEvent
)

// classify sorts one event path and returns a working-tree path relative to
// root. A path outside every known prefix means symlink or case resolution
// missed; it counts as git state so the change still syncs.
func (w *Watcher) classify(path string) (eventKind, string) {
	if w.gitDir != "" {
		if rel, ok := relWithin(w.gitDir, path); ok && (rel == "HEAD" || rel == "index") {
			return gitStateEvent, ""
		}
	}
	if w.refsDir != "" {
		if rel, ok := relWithin(w.refsDir, path); ok {
			// `git maintenance` rewrites refs/prefetch every hour. Status
			// never reads them: ahead and behind come from the upstream.
			if rel == "prefetch" || strings.HasPrefix(rel, "prefetch/") {
				return ignoreEvent, ""
			}
			return gitStateEvent, ""
		}
	}
	if w.gitDir != "" {
		if _, ok := relWithin(w.gitDir, path); ok {
			return ignoreEvent, ""
		}
	}
	rel, ok := relWithin(w.root, path)
	if !ok {
		return gitStateEvent, ""
	}
	if rel == "" {
		return ignoreEvent, ""
	}
	// A nested repository's or linked worktree's own git internals. A
	// linked worktree has its own watcher.
	for part := range strings.SplitSeq(rel, "/") {
		if part == ".git" {
			return ignoreEvent, ""
		}
	}
	return workTreeEvent, rel
}

// record files one FSEvents batch and reports whether any of it can matter.
func (w *Watcher) record(events []fsevents.Event) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	relevant := false
	for _, ev := range events {
		if ev.Flags&droppedEvents != 0 {
			w.dirty = true
			relevant = true
			continue
		}
		switch kind, rel := w.classify(ev.Path); kind {
		case gitStateEvent:
			w.dirty = true
			relevant = true
		case workTreeEvent:
			// A deleted directory no longer exists for git to see that it
			// is one, so `build` would not match a `build/` pattern.
			if ev.Flags&fsevents.ItemIsDir != 0 {
				rel += "/"
			}
			w.paths[rel] = struct{}{}
			relevant = true
		}
	}
	return relevant
}

// flush runs once per debounced burst and calls onChange unless the burst
// touched only paths git ignores. It holds mu around onChange, and Close
// closes w.closed under mu, so onChange never runs after Close returns.
func (w *Watcher) flush() {
	w.mu.Lock()
	dirty, paths := w.dirty, w.paths
	w.dirty, w.paths = false, map[string]struct{}{}
	closed := w.isClosed()
	w.mu.Unlock()
	if closed || (!dirty && !anyNotIgnored(w.root, paths)) {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.isClosed() {
		w.onChange()
	}
}

func (w *Watcher) isClosed() bool {
	select {
	case <-w.closed:
		return true
	default:
		return false
	}
}

// anyNotIgnored reports whether at least one of paths is one git does not
// ignore, with one `git check-ignore` for the whole set. A failed check
// counts as a change: a needless sync is cheap, and a missed one leaves
// stale state on screen.
func anyNotIgnored(root string, paths map[string]struct{}) bool {
	if len(paths) == 0 {
		return false
	}
	var stdin strings.Builder
	for path := range paths {
		stdin.WriteString(path)
		stdin.WriteByte(0)
	}
	cmd := exec.Command("git", "check-ignore", "--stdin", "-z")
	cmd.Dir = root
	cmd.Stdin = strings.NewReader(stdin.String())
	out, err := cmd.Output()
	if err != nil {
		// Exit 1 means none of the paths is ignored. Any other failure
		// counts as a change too.
		return true
	}
	ignored := 0
	for path := range strings.SplitSeq(string(out), "\x00") {
		if _, ok := paths[path]; ok {
			ignored++
		}
	}
	return ignored < len(paths)
}

// pump reads FSEvents batches until Close.
func (w *Watcher) pump() {
	defer close(w.pumpDone)
	for {
		select {
		case <-w.closed:
			return
		case events := <-w.stream.Events:
			if w.record(events) {
				w.debounce.reset()
			}
		}
	}
}

// Close stops the watcher immediately, independent of the shared stop
// channel passed to Run -- used to drop a single worktree's watcher (e.g.
// `git worktree remove`). It is safe to call more than once, and from Run.
// After it returns, onChange is never called again.
func (w *Watcher) Close() error {
	w.closeOnce.Do(func() {
		w.mu.Lock()
		close(w.closed)
		w.mu.Unlock()
		// No debounce reset can follow once the pump is gone.
		<-w.pumpDone
		w.debounce.stop()
		// fsevents' Stop does not wait for a callback that is already
		// running, and that callback blocks on Events while the buffer is
		// full. Draining after Stop frees it, and a later one finds room.
		w.stream.Stop()
		for {
			select {
			case <-w.stream.Events:
			default:
				return
			}
		}
	})
	return nil
}

// Run blocks until stop is closed or the watcher is closed. Events are read
// and debounced from New onward.
func (w *Watcher) Run(stop <-chan struct{}) {
	select {
	case <-stop:
		w.Close()
	case <-w.closed:
	}
}
