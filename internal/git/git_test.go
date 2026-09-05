package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func setupRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	runGitOrFail(t, dir, "init", "-q", "-b", "main")
	runGitOrFail(t, dir, "config", "user.email", "test@example.com")
	runGitOrFail(t, dir, "config", "user.name", "Test User")
	return dir
}

func runGitOrFail(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
	return string(out)
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func commitFile(t *testing.T, dir, name, content string) {
	t.Helper()
	writeFile(t, dir, name, content)
	runGitOrFail(t, dir, "add", name)
	runGitOrFail(t, dir, "commit", "-q", "-m", "add "+name)
}

// TestStatus_UnmergedConflict ensures git status --porcelain=v2 unmerged conflicted paths
// (with "u " prefix) are recognized and reported stat-only.
func TestStatus_UnmergedConflict(t *testing.T) {
	dir := setupRepo(t)
	commitFile(t, dir, "a.txt", "base\n")
	runGitOrFail(t, dir, "checkout", "-q", "-b", "feature")
	writeFile(t, dir, "a.txt", "feature change\n")
	runGitOrFail(t, dir, "commit", "-q", "-am", "feature change")
	runGitOrFail(t, dir, "checkout", "-q", "main")
	writeFile(t, dir, "a.txt", "main change\n")
	runGitOrFail(t, dir, "commit", "-q", "-am", "main change")

	mergeCmd := exec.Command("git", "merge", "-q", "feature")
	mergeCmd.Dir = dir
	_ = mergeCmd.Run() // expected to fail with a conflict; error is not the point here

	ws, changes, err := Status(dir)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !ws.IsDirty {
		t.Fatal("expected IsDirty true during an unresolved conflict")
	}
	if len(changes) != 1 {
		t.Fatalf("expected exactly 1 change for the conflicted path, got %d: %+v", len(changes), changes)
	}
	c := changes[0]
	if c.Path != "a.txt" {
		t.Fatalf("expected conflicted path a.txt, got %q", c.Path)
	}
	if !c.StatOnly || c.StatLine != "conflict" || c.Patch != "" {
		t.Fatalf("expected a stat-only \"conflict\" entry, got %+v", c)
	}
}
