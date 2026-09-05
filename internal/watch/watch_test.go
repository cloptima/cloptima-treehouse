package watch

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// setupGitRepo makes dir a real git repository (via `git init`, not a
// hand-rolled .git directory) so `git check-ignore` -- what addWatches now
// asks to decide directory exclusion -- has a real repo boundary to resolve
// against, matching internal/git's own setupRepo test helper.
func setupGitRepo(t *testing.T, dir string) {
	t.Helper()
	cmd := exec.Command("git", "init", "-q")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init failed: %v\n%s", err, out)
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertWatched(t *testing.T, w *Watcher, path string) {
	t.Helper()
	want := filepath.Clean(path)
	for _, p := range w.WatchedPaths() {
		if filepath.Clean(p) == want {
			return
		}
	}
	t.Fatalf("expected %q to be watched, got %v", path, w.WatchedPaths())
}

func assertNotWatched(t *testing.T, w *Watcher, path string) {
	t.Helper()
	want := filepath.Clean(path)
	for _, p := range w.WatchedPaths() {
		if filepath.Clean(p) == want {
			t.Fatalf("expected %q not to be watched, got %v", path, w.WatchedPaths())
		}
	}
}

// TestAddWatches_MainWorktreeWatchesHeadIndexAndRefs ensures .git/index (the staging area)
// is watched, not just HEAD/refs, so a plain `git add` triggers an fsnotify event.
func TestAddWatches_MainWorktreeWatchesHeadIndexAndRefs(t *testing.T) {
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	mustMkdirAll(t, filepath.Join(gitDir, "refs", "heads"))
	mustWriteFile(t, filepath.Join(gitDir, "HEAD"), "ref: refs/heads/main\n")
	mustWriteFile(t, filepath.Join(gitDir, "index"), "fake-index")

	w, err := New(root, func() {})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	assertWatched(t, w, filepath.Join(gitDir, "HEAD"))
	assertWatched(t, w, filepath.Join(gitDir, "index"))
	assertWatched(t, w, filepath.Join(gitDir, "refs", "heads"))
}

// TestAddWatches_LinkedWorktreeResolvesGitFilePointer verifies that a linked worktree's
// ".git" pointer file is resolved and watched properly.
func TestAddWatches_LinkedWorktreeResolvesGitFilePointer(t *testing.T) {
	mainRoot := t.TempDir()
	mainGitDir := filepath.Join(mainRoot, ".git")
	mustMkdirAll(t, filepath.Join(mainGitDir, "refs", "heads"))
	mustWriteFile(t, filepath.Join(mainGitDir, "HEAD"), "ref: refs/heads/main\n")

	linkedGitDir := filepath.Join(mainGitDir, "worktrees", "feature")
	mustMkdirAll(t, linkedGitDir)
	mustWriteFile(t, filepath.Join(linkedGitDir, "HEAD"), "ref: refs/heads/feature\n")
	mustWriteFile(t, filepath.Join(linkedGitDir, "index"), "fake-index")
	mustWriteFile(t, filepath.Join(linkedGitDir, "commondir"), "../..\n")

	linkedRoot := t.TempDir()
	mustWriteFile(t, filepath.Join(linkedRoot, ".git"), "gitdir: "+linkedGitDir+"\n")

	w, err := New(linkedRoot, func() {})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	assertWatched(t, w, filepath.Join(linkedGitDir, "HEAD"))
	assertWatched(t, w, filepath.Join(linkedGitDir, "index"))
	// Refs are shared through commondir, not the linked worktree's own gitdir.
	assertWatched(t, w, filepath.Join(mainGitDir, "refs", "heads"))
}

// Exclusion is gitignore-driven (git check-ignore), not a hardcoded
// directory-name list -- node_modules here is standing in for any
// ecosystem's own ignored build/cache/dependency directory, proven by
// actually listing it in .gitignore rather than relying on the name itself
// meaning anything to addWatches.
func TestAddWatches_SkipsExcludedDirectories(t *testing.T) {
	root := t.TempDir()
	setupGitRepo(t, root)
	mustWriteFile(t, filepath.Join(root, ".gitignore"), "node_modules/\n")
	mustMkdirAll(t, filepath.Join(root, "node_modules", "pkg"))
	mustMkdirAll(t, filepath.Join(root, "src"))

	w, err := New(root, func() {})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	assertNotWatched(t, w, filepath.Join(root, "node_modules"))
	assertNotWatched(t, w, filepath.Join(root, "node_modules", "pkg"))
	assertWatched(t, w, filepath.Join(root, "src"))
}

// Run calls addWatches on every directory created while the daemon is
// running, which makes that directory the walk root. The exclusion tests
// therefore have to key off the worktree root, not the walk root -- keyed off
// the walk root, an `npm install` mid-session re-entered here with
// root == ".../node_modules", skipped its own exclusion, and watched the
// whole tree.
func TestAddWatches_SkipsExcludedDirectoryEnteredAsItsOwnRoot(t *testing.T) {
	root := t.TempDir()
	setupGitRepo(t, root)
	mustWriteFile(t, filepath.Join(root, ".gitignore"), "node_modules/\n")
	mustMkdirAll(t, filepath.Join(root, "src"))

	w, err := New(root, func() {})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	// Created after the initial walk, exactly as Run's Create branch sees it.
	created := filepath.Join(root, "node_modules")
	mustMkdirAll(t, filepath.Join(created, "pkg", "nested"))
	if err := w.addWatches(created); err != nil {
		t.Fatalf("addWatches: %v", err)
	}

	assertNotWatched(t, w, created)
	assertNotWatched(t, w, filepath.Join(created, "pkg"))
	assertNotWatched(t, w, filepath.Join(created, "pkg", "nested"))
}

// The same walk-root confusion applied to .git: entered as its own root, the
// ".git" branch never fired and the object store -- the largest, highest-churn
// directory in any repo -- was watched in full.
func TestAddWatches_SkipsGitDirEnteredAsItsOwnRoot(t *testing.T) {
	root := t.TempDir()
	gitDir := filepath.Join(root, ".git")
	mustMkdirAll(t, filepath.Join(gitDir, "refs", "heads"))
	mustMkdirAll(t, filepath.Join(gitDir, "objects", "pack"))
	mustWriteFile(t, filepath.Join(gitDir, "HEAD"), "ref: refs/heads/main\n")

	w, err := New(root, func() {})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	if err := w.addWatches(gitDir); err != nil {
		t.Fatalf("addWatches: %v", err)
	}

	assertNotWatched(t, w, filepath.Join(gitDir, "objects"))
	assertNotWatched(t, w, filepath.Join(gitDir, "objects", "pack"))
	// The refs that a live status view genuinely needs are still watched.
	assertWatched(t, w, filepath.Join(gitDir, "refs"))
}

func TestResolveGitDir_Absolute(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	mustMkdirAll(t, target)
	gitFile := filepath.Join(dir, "worktree", ".git")
	mustWriteFile(t, gitFile, "gitdir: "+target+"\n")

	got, err := resolveGitDir(gitFile)
	if err != nil {
		t.Fatalf("resolveGitDir: %v", err)
	}
	if filepath.Clean(got) != filepath.Clean(target) {
		t.Fatalf("got %q, want %q", got, target)
	}
}

func TestResolveGitDir_Relative(t *testing.T) {
	dir := t.TempDir()
	mustMkdirAll(t, filepath.Join(dir, "main", ".git", "worktrees", "feature"))
	gitFile := filepath.Join(dir, "feature-worktree", ".git")
	mustWriteFile(t, gitFile, "gitdir: ../main/.git/worktrees/feature\n")

	got, err := resolveGitDir(gitFile)
	if err != nil {
		t.Fatalf("resolveGitDir: %v", err)
	}
	want := filepath.Join(dir, "main", ".git", "worktrees", "feature")
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestResolveGitDir_UnrecognizedFormat(t *testing.T) {
	dir := t.TempDir()
	gitFile := filepath.Join(dir, ".git")
	mustWriteFile(t, gitFile, "not a gitdir pointer\n")

	if _, err := resolveGitDir(gitFile); err == nil {
		t.Fatal("expected an error for an unrecognized .git pointer file")
	}
}

func TestCommonDir_ResolvesRelativePointer(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, "main", ".git", "worktrees", "feature")
	mustMkdirAll(t, gitDir)
	mustWriteFile(t, filepath.Join(gitDir, "commondir"), "../..\n")

	got := commonDir(gitDir)
	want := filepath.Join(dir, "main", ".git")
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCommonDir_AbsentReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	if got := commonDir(dir); got != "" {
		t.Fatalf("expected empty string when commondir is absent, got %q", got)
	}
}
