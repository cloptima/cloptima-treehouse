//go:build darwin && cgo

package watch

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsevents"
)

func openDescriptors(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// kqueue held one descriptor per watched file and directory, tens of
// thousands on a large repo, copied into every git subprocess the daemon
// spawned.
func TestNewHoldsNoDescriptorPerWatchedFile(t *testing.T) {
	root := t.TempDir()
	setupGitRepo(t, root)
	for d := range 20 {
		for f := range 10 {
			mustWriteFile(t, filepath.Join(root, fmt.Sprintf("dir%d", d), fmt.Sprintf("f%d.txt", f)), "x\n")
		}
	}

	before := openDescriptors(t)
	w, err := New(root, func() {})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	if grown := openDescriptors(t) - before; grown > 5 {
		t.Fatalf("watching 220 paths opened %d descriptors", grown)
	}
}

// t.TempDir sits under /var, a symlink to /private/var, and FSEvents reports
// the resolved path. An unresolved root would never match an event.
func TestRunSyncsAfterAWorkingTreeEdit(t *testing.T) {
	root := t.TempDir()
	setupGitRepo(t, root)
	mustWriteFile(t, filepath.Join(root, ".gitignore"), "node_modules/\n")

	changed := make(chan struct{}, 1)
	w, err := New(root, func() {
		select {
		case changed <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	stop := make(chan struct{})
	ran := make(chan struct{})
	go func() {
		w.Run(stop)
		close(ran)
	}()

	mustWriteFile(t, filepath.Join(root, "src", "main.go"), "package main\n")
	select {
	case <-changed:
	case <-time.After(syncDebounce + 5*time.Second):
		t.Fatal("no sync after a working-tree edit")
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after Close")
	}
}

// A linked worktree's HEAD and index live in the main repo's
// .git/worktrees/<name>, and its refs in the main .git. Neither is under the
// worktree root, so a commit there is seen only if the stream covers them.
func TestNewStreamsALinkedWorktreesGitDirAndSharedRefs(t *testing.T) {
	mainRoot := realPath(t.TempDir())
	mainGitDir := filepath.Join(mainRoot, ".git")
	mustMkdirAll(t, filepath.Join(mainGitDir, "refs", "heads"))
	linkedGitDir := filepath.Join(mainGitDir, "worktrees", "feature")
	mustWriteFile(t, filepath.Join(linkedGitDir, "HEAD"), "ref: refs/heads/feature\n")
	mustWriteFile(t, filepath.Join(linkedGitDir, "commondir"), "../..\n")
	linkedRoot := realPath(t.TempDir())
	mustWriteFile(t, filepath.Join(linkedRoot, ".git"), "gitdir: "+linkedGitDir+"\n")

	w, err := New(linkedRoot, func() {})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	refsDir := filepath.Join(mainGitDir, "refs")
	for _, want := range []string{linkedRoot, linkedGitDir, refsDir} {
		if !slices.Contains(w.stream.Paths, want) {
			t.Fatalf("stream paths %v miss %s", w.stream.Paths, want)
		}
	}
	if kind, _ := w.classify(filepath.Join(linkedGitDir, "HEAD")); kind != gitStateEvent {
		t.Fatal("the linked worktree's HEAD must count as git state")
	}
	if kind, _ := w.classify(filepath.Join(refsDir, "heads", "feature")); kind != gitStateEvent {
		t.Fatal("a shared ref must count as git state")
	}
}

// `git worktree list` keeps the case a worktree path was typed with, and
// FSEvents reports the case on disk. A mismatch sent every event, ignored
// build output included, straight to a sync.
func TestClassifyIgnoresCaseInRoots(t *testing.T) {
	w := &Watcher{root: "/Users/me/Repo/LinkedWT", gitDir: "/Users/me/Repo/.git/worktrees/LinkedWT", refsDir: "/Users/me/Repo/.git/refs"}
	for _, tc := range []struct {
		path string
		kind eventKind
		rel  string
	}{
		{"/users/me/repo/linkedwt/node_modules/x.js", workTreeEvent, "node_modules/x.js"},
		{"/USERS/ME/REPO/.GIT/worktrees/linkedwt/HEAD", gitStateEvent, ""},
		{"/users/me/repo/.git/refs/heads/main", gitStateEvent, ""},
		{"/users/me/repo/linkedwtx/a.go", gitStateEvent, ""},
	} {
		kind, rel := w.classify(tc.path)
		if kind != tc.kind || rel != tc.rel {
			t.Fatalf("classify(%q) = %v, %q; want %v, %q", tc.path, kind, rel, tc.kind, tc.rel)
		}
	}
}

func TestClassify(t *testing.T) {
	w := &Watcher{root: "/r", gitDir: "/r/.git", refsDir: "/r/.git/refs"}
	for _, tc := range []struct {
		path string
		kind eventKind
		rel  string
	}{
		{"/r/.git/HEAD", gitStateEvent, ""},
		{"/r/.git/index", gitStateEvent, ""},
		{"/r/.git/refs/heads/main", gitStateEvent, ""},
		{"/r/.git/refs/remotes/origin/main", gitStateEvent, ""},
		{"/r/.git/index.lock", ignoreEvent, ""},
		{"/r/.git/objects/ab/cdef", ignoreEvent, ""},
		{"/r/.git/logs/HEAD", ignoreEvent, ""},
		{"/r/.git/worktrees/other/HEAD", ignoreEvent, ""},
		{"/r", ignoreEvent, ""},
		{"/r/src/main.go", workTreeEvent, "src/main.go"},
		{"/r/.gitignore", workTreeEvent, ".gitignore"},
		{"/r/vendor/lib/.git/objects/ab", ignoreEvent, ""},
		{"/r/nested/worktree/.git", ignoreEvent, ""},
		// Prefix matching is by path element, not by string.
		{"/r/.gitx/HEAD", workTreeEvent, ".gitx/HEAD"},
		{"/rr/src/main.go", gitStateEvent, ""},
		// `git maintenance` prefetch refs never change what status shows.
		{"/r/.git/refs/prefetch/remotes/origin/main", ignoreEvent, ""},
		{"/r/.git/refs/prefetchx", gitStateEvent, ""},
	} {
		kind, rel := w.classify(tc.path)
		if kind != tc.kind || rel != tc.rel {
			t.Fatalf("classify(%q) = %v, %q; want %v, %q", tc.path, kind, rel, tc.kind, tc.rel)
		}
	}
}

// FSEvents reports every path, including ignored build output. A burst of
// nothing but ignored paths must not sync, or `npm install` and every build
// would push a snapshot.
func TestFlushSkipsABurstOfIgnoredPathsOnly(t *testing.T) {
	root := realPath(t.TempDir())
	setupGitRepo(t, root)
	mustWriteFile(t, filepath.Join(root, ".gitignore"), "node_modules/\n*.log\n")
	var calls atomic.Int32
	w := &Watcher{root: root, gitDir: filepath.Join(root, ".git"), refsDir: filepath.Join(root, ".git", "refs"),
		onChange: func() { calls.Add(1) }, paths: map[string]struct{}{}}
	event := func(rel string) fsevents.Event { return fsevents.Event{Path: filepath.Join(root, rel)} }

	if w.record([]fsevents.Event{event(".git/objects/ab/cdef")}) {
		t.Fatal("an object-store write must not start a debounce")
	}

	w.record([]fsevents.Event{event("node_modules/pkg/index.js"), event("build.log")})
	w.flush()
	if calls.Load() != 0 {
		t.Fatal("a burst of ignored paths synced")
	}

	w.record([]fsevents.Event{event("node_modules/pkg/index.js"), event("src/main.go")})
	w.flush()
	if calls.Load() != 1 {
		t.Fatal("a burst with a tracked path did not sync")
	}

	w.record([]fsevents.Event{event(".git/index")})
	w.flush()
	if calls.Load() != 2 {
		t.Fatal("an index change did not sync")
	}

	w.record([]fsevents.Event{{Path: filepath.Join(root, "node_modules"), Flags: fsevents.MustScanSubDirs}})
	w.flush()
	if calls.Load() != 3 {
		t.Fatal("dropped events did not sync")
	}

	// `rm -rf build`: the directory no longer exists, so only the trailing
	// slash tells git that a `build/` pattern applies.
	mustWriteFile(t, filepath.Join(root, ".gitignore"), "node_modules/\n*.log\nbuild/\n")
	w.record([]fsevents.Event{{Path: filepath.Join(root, "build"), Flags: fsevents.ItemIsDir | fsevents.ItemRemoved}})
	w.flush()
	if calls.Load() != 3 {
		t.Fatal("a deleted ignored directory synced")
	}

	w.flush()
	if calls.Load() != 3 {
		t.Fatal("an empty flush synced")
	}
}

// git ignores rules for a tracked file, even inside an ignored directory, so
// an edit to it must sync.
func TestFlushSyncsATrackedFileInsideAnIgnoredDirectory(t *testing.T) {
	root := realPath(t.TempDir())
	setupGitRepo(t, root)
	mustWriteFile(t, filepath.Join(root, ".gitignore"), "build/\n")
	mustWriteFile(t, filepath.Join(root, "build", "keep.txt"), "keep\n")
	add := exec.Command("git", "add", "-f", "build/keep.txt")
	add.Dir = root
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
	var calls atomic.Int32
	w := &Watcher{root: root, gitDir: filepath.Join(root, ".git"), refsDir: filepath.Join(root, ".git", "refs"),
		onChange: func() { calls.Add(1) }, paths: map[string]struct{}{}}

	w.record([]fsevents.Event{{Path: filepath.Join(root, "build", "keep.txt")}, {Path: filepath.Join(root, "build", "out.o")}})
	w.flush()
	if calls.Load() != 1 {
		t.Fatal("an edit to a tracked file inside an ignored directory did not sync")
	}
}

// A sync after Close pushed a snapshot for a worktree or repo the daemon had
// just stopped watching.
func TestNoChangeIsReportedAfterClose(t *testing.T) {
	root := t.TempDir()
	setupGitRepo(t, root)
	var calls atomic.Int32
	w, err := New(root, func() { calls.Add(1) })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	w.record([]fsevents.Event{{Path: filepath.Join(w.root, ".git", "HEAD")}})
	w.flush()
	if calls.Load() != 0 {
		t.Fatal("onChange ran after Close")
	}
}
