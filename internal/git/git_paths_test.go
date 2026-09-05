package git

import (
	"strings"
	"testing"
)

func changeFor(t *testing.T, changes []FileChange, path string) FileChange {
	t.Helper()
	for _, c := range changes {
		if c.Path == path {
			return c
		}
	}
	var got []string
	for _, c := range changes {
		got = append(got, c.Path)
	}
	t.Fatalf("no change reported for %q; got %v", path, got)
	return FileChange{}
}

// git status collapses an untracked directory into a single "? dir/" entry
// unless asked otherwise (--untracked-files=all), which allows real files
// inside untracked directories to be discovered and diffed.
func TestStatusListsFilesInsideANewUntrackedDirectory(t *testing.T) {
	dir := setupRepo(t)
	writeFile(t, dir, "README.md", "seed\n")
	runGitOrFail(t, dir, "add", "README.md")
	runGitOrFail(t, dir, "commit", "-qm", "seed")

	writeFile(t, dir, "feature/handler.go", "package feature\n")
	writeFile(t, dir, "feature/internal/util.go", "package internal\n")

	ws, changes, err := Status(dir)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !ws.IsDirty {
		t.Fatal("a worktree with new untracked files is dirty")
	}

	for _, path := range []string{"feature/handler.go", "feature/internal/util.go"} {
		c := changeFor(t, changes, path)
		if c.Patch == "" {
			t.Fatalf("%s should carry a patch, got none", path)
		}
		if c.StatLine == "" {
			t.Fatalf("%s should carry a stat line, got none", path)
		}
	}
	for _, c := range changes {
		if strings.HasSuffix(c.Path, "/") {
			t.Fatalf("a directory (%q) must never be reported as a file", c.Path)
		}
	}
}

// Porcelain output C-quotes any path with a control character, a quote, a
// backslash, or -- with core.quotePath at its default -- a non-ASCII byte.
// Passing that quoted form back as a pathspec matches nothing and exits 0,
// which silently produced an entry with no stat line and no patch.
func TestStatusHandlesQuotedAndGlobbyPaths(t *testing.T) {
	dir := setupRepo(t)
	writeFile(t, dir, "README.md", "seed\n")
	runGitOrFail(t, dir, "add", "README.md")
	runGitOrFail(t, dir, "commit", "-qm", "seed")

	// core.quotePath defaults to true, but a developer machine may have it
	// off; force it on so this test exercises the quoted form either way.
	runGitOrFail(t, dir, "config", "core.quotepath", "true")

	awkward := map[string]string{
		"café/menü.go":        "package cafe\n",
		"reports/[draft].md":  "# draft\n",
		"queries/where?.sql":  "SELECT 1;\n",
		"globs/star*name.txt": "x\n",
	}
	for name, content := range awkward {
		writeFile(t, dir, name, content)
	}
	runGitOrFail(t, dir, "add", "-A")

	_, changes, err := Status(dir)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}

	for name := range awkward {
		c := changeFor(t, changes, name)
		if c.StatOnly {
			t.Fatalf("%s should not have degraded to stat-only", name)
		}
		if c.Patch == "" {
			t.Fatalf("%s should carry a patch, got none", name)
		}
	}
}

func TestUnquotePath(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`plain.txt`, `plain.txt`},
		{`spaced name.txt`, `spaced name.txt`},
		{`"tab\tname.txt"`, "tab\tname.txt"},
		{`"uni-caf\303\251.txt"`, "uni-café.txt"},
		{`"quote\"name.txt"`, `quote"name.txt`},
		{`"back\\slash.txt"`, `back\slash.txt`},
		// Anything that does not parse is returned untouched rather than
		// mangled into something that matches a different file.
		{`"unterminated`, `"unterminated`},
	} {
		if got := unquotePath(tc.in); got != tc.want {
			t.Fatalf("unquotePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// `git diff` exits 1 for "differences found", which is normal, but
// `git diff --no-index` also exits 1 for real failures. Tolerating every
// exit-1 turned those failures into empty diffs.
func TestRunGitDistinguishesDifferencesFromFailure(t *testing.T) {
	dir := setupRepo(t)
	writeFile(t, dir, "a.txt", "one\n")
	runGitOrFail(t, dir, "add", "a.txt")
	runGitOrFail(t, dir, "commit", "-qm", "seed")
	writeFile(t, dir, "a.txt", "two\n")

	out, err := runGit(dir, "diff", "--numstat", "--", literalPathspec("a.txt"))
	if err != nil {
		t.Fatalf("a diff with differences must not be an error: %v", err)
	}
	if out == "" {
		t.Fatal("expected numstat output for a modified file")
	}

	if _, err := runGit(dir, "diff", "--no-index", "--numstat", "--", "/dev/null", "definitely-missing-path"); err == nil {
		t.Fatal("a --no-index failure must be reported as an error, not an empty diff")
	}
}

func TestRunGitReportsAMissingSubcommandWithAReason(t *testing.T) {
	dir := setupRepo(t)
	_, err := runGit(dir, "definitely-not-a-git-subcommand")
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.TrimSpace(err.Error()) == "" {
		t.Fatal("the error must carry a reason; an empty message is what the old code produced")
	}
}
