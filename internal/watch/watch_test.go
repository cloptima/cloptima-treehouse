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
