package git

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// countGitCalls puts a logging git wrapper first on PATH and returns a func
// reporting how many git processes ran since.
func countGitCalls(t *testing.T) func() int {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the counting wrapper is a shell script")
	}
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\necho x >> '" + logPath + "'\nexec '" + realGit + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() int {
		data, err := os.ReadFile(logPath)
		if os.IsNotExist(err) {
			return 0
		}
		if err != nil {
			t.Fatal(err)
		}
		return bytes.Count(data, []byte("\n"))
	}
}

// One diff per changed file cost about 300 git spawns per sync on a busy
// worktree.
func TestStatusGitCallsDoNotScaleWithChangedFiles(t *testing.T) {
	dir := setupRepo(t)
	for i := range 40 {
		writeFile(t, dir, filepath.Join("pkg", string(rune('a'+i%26))+strings.Repeat("x", i/26)+".txt"), "one\n")
	}
	runGitOrFail(t, dir, "add", "-A")
	runGitOrFail(t, dir, "commit", "-qm", "seed")
	entries, err := os.ReadDir(filepath.Join(dir, "pkg"))
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range entries {
		writeFile(t, dir, filepath.Join("pkg", e.Name()), "two\n")
		if i%2 == 0 {
			runGitOrFail(t, dir, "add", filepath.Join("pkg", e.Name()))
		}
	}
	for i := range 30 {
		writeFile(t, dir, filepath.Join("new", "deep", fmt.Sprintf("f%d.txt", i)), "new\n")
	}
	// A nested repository is reported stat-only, without a process.
	runGitOrFail(t, dir, "init", "-q", "nested")

	calls := countGitCalls(t)
	_, changes, err := Status(dir)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(changes) != 71 {
		t.Fatalf("expected 71 changes, got %d", len(changes))
	}
	for _, c := range changes {
		if c.Patch == "" && c.Path != "nested/" {
			t.Fatalf("%s has no patch", c.Path)
		}
	}
	if c := changeFor(t, changes, "nested/"); !c.StatOnly || c.StatLine != "diff unavailable" {
		t.Fatalf("a nested repository must be stat-only, got %+v", c)
	}
	// status, one staged diff, one unstaged diff, and add -N plus one diff
	// for the untracked files.
	if got := calls(); got != 5 {
		t.Fatalf("expected 5 git calls for 40 tracked and 30 untracked changes, got %d", got)
	}
}

// oldGit runs git the way the per-file Status did: no pinned patch format,
// and exit 1 with nothing on stderr counts as "differences found".
func oldGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var exitErr *exec.ExitError
	if err != nil && !(errors.As(err, &exitErr) && exitErr.ExitCode() == 1 && stderr.Len() == 0) {
		t.Fatalf("git %v: %v\n%s", args, err, stderr.String())
	}
	return string(out)
}

// oldPerFileDiff is what the per-file Status sent for one change: a numstat
// call, then a patch call unless numstat said binary.
func oldPerFileDiff(t *testing.T, dir string, c FileChange, untracked bool) (statLine, patch string, binary bool) {
	t.Helper()
	var numstatArgs, patchArgs []string
	switch {
	case untracked:
		numstatArgs = []string{"diff", "--no-index", "--numstat", "--", "/dev/null", c.Path}
		patchArgs = []string{"diff", "--no-index", "--", "/dev/null", c.Path}
	case c.Staged:
		numstatArgs = []string{"diff", "--staged", "--numstat", "--", ":(literal)" + c.Path}
		patchArgs = []string{"diff", "--staged", "--", ":(literal)" + c.Path}
	default:
		numstatArgs = []string{"diff", "--numstat", "--", ":(literal)" + c.Path}
		patchArgs = []string{"diff", "--", ":(literal)" + c.Path}
	}
	numstat := oldGit(t, dir, numstatArgs...)
	binary = numstatIsBinary(numstat)
	if !binary {
		patch = oldGit(t, dir, patchArgs...)
	}
	return statLineFromNumstat(numstat), patch, binary
}

// addSubmoduleWithNewCommit adds a submodule at sub and moves it one commit
// ahead of what the superproject records.
func addSubmoduleWithNewCommit(t *testing.T, dir string) {
	t.Helper()
	src := setupRepo(t)
	commitFile(t, src, "s.txt", "one\n")
	runGitOrFail(t, dir, "-c", "protocol.file.allow=always", "submodule", "--quiet", "add", src, "sub")
	runGitOrFail(t, dir, "commit", "-qm", "add sub")
	sub := filepath.Join(dir, "sub")
	runGitOrFail(t, sub, "config", "user.email", "test@example.com")
	runGitOrFail(t, sub, "config", "user.name", "Test User")
	commitFile(t, sub, "s.txt", "two\n")
}

// The server and its readers consume the patch text, so the batched diffs must
// send what the per-file diffs sent, byte for byte, for every kind of change.
func TestStatusMatchesThePerFileDiffs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks, exec bits, and tab file names")
	}
	// Hermetic: a developer's global diff config would change the old
	// commands' output, which never pinned the format.
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	dir := setupRepo(t)
	runGitOrFail(t, dir, "config", "core.quotepath", "true")
	tracked := map[string]string{
		"modified.txt": "one\ntwo\n", "staged.txt": "one\n", "both.txt": "one\n",
		"deleted.txt": "gone\n", "staged-delete.txt": "gone\n", "mode.sh": "#!/bin/sh\n",
		"typechange": "plain\n", "image.bin": "\x00\x01", "renamed-from.txt": "move me\n",
		"spaced name.txt": "x\n", "tab\tname.txt": "x\n", "café.txt": "x\n", "star*[x].txt": "x\n",
	}
	for name, content := range tracked {
		writeFile(t, dir, name, content)
	}
	runGitOrFail(t, dir, "add", "-A")
	runGitOrFail(t, dir, "commit", "-qm", "seed")
	addSubmoduleWithNewCommit(t, dir)

	writeFile(t, dir, "modified.txt", "one\nTWO\n")
	writeFile(t, dir, "staged.txt", "staged\n")
	runGitOrFail(t, dir, "add", "staged.txt")
	writeFile(t, dir, "both.txt", "staged\n")
	runGitOrFail(t, dir, "add", "both.txt")
	writeFile(t, dir, "both.txt", "staged\nunstaged\n")
	if err := os.Remove(filepath.Join(dir, "deleted.txt")); err != nil {
		t.Fatal(err)
	}
	runGitOrFail(t, dir, "rm", "-q", "staged-delete.txt")
	if err := os.Chmod(filepath.Join(dir, "mode.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "typechange")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("modified.txt", filepath.Join(dir, "typechange")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "image.bin", "\x00\x02")
	runGitOrFail(t, dir, "mv", "renamed-from.txt", "renamed-to.txt")
	for _, name := range []string{"spaced name.txt", "tab\tname.txt", "café.txt", "star*[x].txt"} {
		writeFile(t, dir, name, "edited\n")
	}

	untracked := map[string]string{
		"new/text.txt": "line1\nline2\n", "new/empty.txt": "", "new/no-newline.txt": "no newline",
		"new/crlf.txt": "a\r\nb\r\n", "new/blob.bin": "\x00\x01\x02", "new/spaced name.txt": "x\n",
		"new/tab\tname.txt": "x\n", "new/menü.go": "package cafe\n", "new/star*[x].txt": "x\n",
	}
	for name, content := range untracked {
		writeFile(t, dir, name, content)
	}
	writeFile(t, dir, "new/run.sh", "#!/bin/sh\n")
	if err := os.Chmod(filepath.Join(dir, "new", "run.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("text.txt", filepath.Join(dir, "new", "link")); err != nil {
		t.Fatal(err)
	}
	untracked["new/run.sh"], untracked["new/link"] = "", ""

	_, changes, err := Status(dir)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	// 15 tracked entries (both.txt twice, the rename as its new path, sub)
	// and 11 untracked files.
	if len(changes) != 26 {
		t.Fatalf("expected 26 changes, got %d: %+v", len(changes), changes)
	}
	for _, c := range changes {
		_, isUntracked := untracked[c.Path]
		statLine, patch, binary := oldPerFileDiff(t, dir, c, isUntracked)
		if c.StatLine != statLine || c.Binary != binary || c.Patch != patch {
			t.Fatalf("%s (staged=%v): differs from the per-file diff\ngot  %q %v\n%s\nwant %q %v\n%s",
				c.Path, c.Staged, c.StatLine, c.Binary, c.Patch, statLine, binary, patch)
		}
	}
}

// One bad file fails the whole batched diff. The other new files must still
// get their patches from the per-file fallback.
func TestStatusFallsBackPerFileWhenTheUntrackedBatchFails(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("needs a file the current user cannot read")
	}
	dir := setupRepo(t)
	commitFile(t, dir, "seed.txt", "seed\n")
	writeFile(t, dir, "fine.txt", "fine\n")
	writeFile(t, dir, "locked.txt", "locked\n")
	locked := filepath.Join(dir, "locked.txt")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o644) })
	if _, err := diffUntrackedBatch(dir, []string{"fine.txt", "locked.txt"}); err == nil {
		t.Fatal("expected the batch to fail on an unreadable file")
	}

	_, changes, err := Status(dir)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if fine := changeFor(t, changes, "fine.txt"); fine.StatLine != "+1 -0" || !strings.Contains(fine.Patch, "+fine\n") {
		t.Fatalf("fine.txt lost its patch when the batch failed: %+v", fine)
	}
	if c := changeFor(t, changes, "locked.txt"); !c.StatOnly || c.StatLine != "diff unavailable" {
		t.Fatalf("expected locked.txt stat-only, got %+v", c)
	}
}

// Every path's patch must come from its own section of the batched diff. A
// misaligned split would hand one file's patch to another.
func TestStatusAttributesEachPatchToItsOwnPathAndSide(t *testing.T) {
	dir := setupRepo(t)
	commitFile(t, dir, "both.txt", "base\n")
	commitFile(t, dir, "only-staged.txt", "base\n")
	commitFile(t, dir, "spaced name.txt", "base\n")
	commitFile(t, dir, "image.bin", "\x00\x01base")

	writeFile(t, dir, "both.txt", "staged\n")
	runGitOrFail(t, dir, "add", "both.txt")
	writeFile(t, dir, "both.txt", "staged\nunstaged\n")
	writeFile(t, dir, "only-staged.txt", "only staged\n")
	runGitOrFail(t, dir, "add", "only-staged.txt")
	writeFile(t, dir, "spaced name.txt", "spaced edit\n")
	writeFile(t, dir, "image.bin", "\x00\x02edit")

	_, changes, err := Status(dir)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}

	byKey := map[string]FileChange{}
	for _, c := range changes {
		key := c.Path + "|unstaged"
		if c.Staged {
			key = c.Path + "|staged"
		}
		byKey[key] = c
	}
	for key, want := range map[string]struct{ header, added, stat string }{
		"both.txt|staged":          {"diff --git a/both.txt b/both.txt\n", "+staged\n", "+1 -1"},
		"both.txt|unstaged":        {"diff --git a/both.txt b/both.txt\n", "+unstaged\n", "+1 -0"},
		"only-staged.txt|staged":   {"diff --git a/only-staged.txt b/only-staged.txt\n", "+only staged\n", "+1 -1"},
		"spaced name.txt|unstaged": {"diff --git a/spaced name.txt b/spaced name.txt\n", "+spaced edit\n", "+1 -1"},
	} {
		c, ok := byKey[key]
		if !ok {
			t.Fatalf("missing change %s; got %v", key, changes)
		}
		if !strings.HasPrefix(c.Patch, want.header) || strings.Count(c.Patch, "diff --git ") != 1 {
			t.Fatalf("%s: patch must be exactly its own section, got:\n%s", key, c.Patch)
		}
		if !strings.Contains(c.Patch, want.added) || c.StatLine != want.stat {
			t.Fatalf("%s: wrong content or stat %q:\n%s", key, c.StatLine, c.Patch)
		}
	}
	if strings.Contains(byKey["both.txt|staged"].Patch, "unstaged") {
		t.Fatal("the staged side must not carry the unstaged edit")
	}

	bin := byKey["image.bin|unstaged"]
	if !bin.Binary || bin.Patch != "" || bin.StatLine != "binary file changed" {
		t.Fatalf("a binary file must be stat-lined with no patch, got %+v", bin)
	}
}

// A typechange comes back as two sections under one path: the deletion of
// the old file and the creation of the symlink. Both belong to that path.
func TestStatusKeepsBothSectionsOfATypechange(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	dir := setupRepo(t)
	commitFile(t, dir, "target.txt", "target\n")
	commitFile(t, dir, "link", "plain file\n")
	if err := os.Remove(filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.txt", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}

	_, changes, err := Status(dir)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	c := changeFor(t, changes, "link")
	if !strings.Contains(c.Patch, "deleted file mode 100644") || !strings.Contains(c.Patch, "new file mode 120000") {
		t.Fatalf("expected both typechange sections, got:\n%s", c.Patch)
	}
}

// git prints a conflicted path's combined diff before the numstat records.
// Left in, it corrupted the split, and every other file lost its stat line.
func TestStatusDiffsOtherFilesDuringAConflict(t *testing.T) {
	dir := setupRepo(t)
	commitFile(t, dir, "conflict.txt", "base\n")
	commitFile(t, dir, "other.txt", "base\n")
	runGitOrFail(t, dir, "checkout", "-q", "-b", "feature")
	writeFile(t, dir, "conflict.txt", "feature\n")
	runGitOrFail(t, dir, "commit", "-q", "-am", "feature")
	runGitOrFail(t, dir, "checkout", "-q", "main")
	writeFile(t, dir, "conflict.txt", "main\n")
	runGitOrFail(t, dir, "commit", "-q", "-am", "main")
	merge := exec.Command("git", "merge", "-q", "feature")
	merge.Dir = dir
	_ = merge.Run() // conflicts on purpose
	writeFile(t, dir, "other.txt", "edited\n")

	_, changes, err := Status(dir)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	other := changeFor(t, changes, "other.txt")
	if other.StatLine != "+1 -1" || !strings.HasPrefix(other.Patch, "diff --git a/other.txt b/other.txt\n") {
		t.Fatalf("other.txt lost its diff during a conflict: %+v", other)
	}
	if conflict := changeFor(t, changes, "conflict.txt"); !conflict.StatOnly || conflict.StatLine != "conflict" {
		t.Fatalf("expected a stat-only conflict entry, got %+v", conflict)
	}
}

// Patches are split on their "diff --git" headers, so no user diff setting
// may move, colour, replace, or add to them. Before the format was pinned,
// diff.submodule=log appended the submodule's log to the previous file's
// patch, and color.ui=always or diff.external left every patch empty.
func TestStatusPatchesIgnoreUserDiffConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the external diff is a shell script")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	dir := setupRepo(t)
	commitFile(t, dir, "a.txt", "one\n")
	addSubmoduleWithNewCommit(t, dir)
	writeFile(t, dir, "a.txt", "two\n")
	writeFile(t, dir, "new.txt", "new\n")
	external := filepath.Join(t.TempDir(), "external-diff")
	if err := os.WriteFile(external, []byte("#!/bin/sh\necho EXTERNAL\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, baseline, err := Status(dir)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(baseline) != 3 {
		t.Fatalf("expected a.txt, sub, and new.txt, got %+v", baseline)
	}
	for _, cfg := range [][2]string{
		{"diff.noprefix", "true"},
		{"diff.mnemonicPrefix", "true"},
		{"color.ui", "always"},
		{"color.diff", "always"},
		{"diff.external", external},
		{"diff.submodule", "log"},
		{"diff.submodule", "diff"},
	} {
		runGitOrFail(t, dir, "config", cfg[0], cfg[1])
		_, changes, err := Status(dir)
		if err != nil {
			t.Fatalf("%s=%s: Status: %v", cfg[0], cfg[1], err)
		}
		if !slices.Equal(changes, baseline) {
			t.Fatalf("%s=%s changed the snapshot\ngot  %+v\nwant %+v", cfg[0], cfg[1], changes, baseline)
		}
		runGitOrFail(t, dir, "config", "--unset", cfg[0])
	}
}

// Git config can also come from the environment (GIT_CONFIG_COUNT), which
// headless installs use for settings like safe.directory. The daemon's own
// settings must add to it, not replace it.
func TestStatusKeepsConfigFromTheEnvironment(t *testing.T) {
	dir := setupRepo(t)
	commitFile(t, dir, "a.txt", "a\nb\nc\n")
	writeFile(t, dir, "a.txt", "a\nB\nc\n")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "diff.context")
	t.Setenv("GIT_CONFIG_VALUE_0", "0")

	_, changes, err := Status(dir)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if patch := changeFor(t, changes, "a.txt").Patch; strings.Contains(patch, "\n a\n") {
		t.Fatalf("diff.context=0 from the environment was dropped:\n%s", patch)
	}
}

// A worktree deleted without `git worktree remove` stays listed as prunable
// until `git worktree prune`. Watching it failed and was retried every poll.
func TestListWorktreesSkipsPrunableWorktrees(t *testing.T) {
	dir := setupRepo(t)
	commitFile(t, dir, "a.txt", "a\n")
	kept := filepath.Join(t.TempDir(), "kept")
	gone := filepath.Join(t.TempDir(), "gone")
	runGitOrFail(t, dir, "worktree", "add", "-q", kept)
	runGitOrFail(t, dir, "worktree", "add", "-q", gone)
	if err := os.RemoveAll(gone); err != nil {
		t.Fatal(err)
	}

	paths, err := ListWorktrees(dir)
	if err != nil {
		t.Fatalf("ListWorktrees: %v", err)
	}
	if len(paths) != 2 || slices.ContainsFunc(paths, func(p string) bool { return strings.HasSuffix(p, "/gone") }) {
		t.Fatalf("expected the main and kept worktrees only, got %v", paths)
	}
}

// The discovery poll runs `git worktree list` only when this stamp moves, so
// it must move for every change that list would show.
func TestWorktreesStampMovesWithEveryWorktreeChange(t *testing.T) {
	dir := setupRepo(t)
	commitFile(t, dir, "a.txt", "a\n")
	common, err := CommonDir(dir)
	if err != nil {
		t.Fatalf("CommonDir: %v", err)
	}
	base := t.TempDir()
	wt, moved := filepath.Join(base, "wt"), filepath.Join(base, "moved")

	stamp := WorktreesStamp(common)
	if WorktreesStamp(common) != stamp {
		t.Fatal("the stamp moved with nothing changed")
	}
	for _, step := range []struct {
		name string
		do   func()
	}{
		{"add", func() { runGitOrFail(t, dir, "worktree", "add", "-q", wt) }},
		{"move", func() { runGitOrFail(t, dir, "worktree", "move", wt, moved) }},
		{"delete the directory", func() {
			if err := os.RemoveAll(moved); err != nil {
				t.Fatal(err)
			}
		}},
		{"prune", func() { runGitOrFail(t, dir, "worktree", "prune") }},
	} {
		step.do()
		next := WorktreesStamp(common)
		if next == stamp {
			t.Fatalf("the stamp did not move after %s", step.name)
		}
		stamp = next
	}
}

// gitDirState records every file under dir/.git by size and mtime.
func gitDirState(t *testing.T, dir string) map[string]string {
	t.Helper()
	state := map[string]string{}
	err := filepath.WalkDir(filepath.Join(dir, ".git"), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		state[path] = fmt.Sprint(info.Size(), info.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// By default `git status` and `git diff` rewrite .git/index to refresh stat
// data, and `git add -N` writes the empty blob. The daemon must not write to
// a repo it watches, and a write under .git is a change event the watcher
// would answer with another sync.
func TestStatusNeverWritesToTheGitDir(t *testing.T) {
	for _, splitIndex := range []bool{false, true} {
		dir := setupRepo(t)
		if splitIndex {
			runGitOrFail(t, dir, "config", "core.splitIndex", "true")
		}
		commitFile(t, dir, "touched.txt", "same\n")
		commitFile(t, dir, "edited.txt", "one\n")
		future := time.Now().Add(time.Hour)
		if err := os.Chtimes(filepath.Join(dir, "touched.txt"), future, future); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, "edited.txt", "two\n")
		writeFile(t, dir, "new.txt", "new\n")
		writeFile(t, dir, "empty.txt", "")
		before := gitDirState(t, dir)

		_, changes, err := Status(dir)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if len(changes) != 3 {
			t.Fatalf("a stat-only touch is not a change; got %+v", changes)
		}
		after := gitDirState(t, dir)
		if splitIndex {
			// Every read of a split index refreshes the shared index's
			// mtime; that is git's read path. A daemon write here is a new
			// file: the throwaway index's own shared index.
			if !slices.Equal(slices.Sorted(maps.Keys(before)), slices.Sorted(maps.Keys(after))) {
				t.Fatalf("Status added or removed files under .git\nbefore %v\nafter  %v", before, after)
			}
		} else if !maps.Equal(before, after) {
			t.Fatalf("Status wrote under .git\nbefore %v\nafter  %v", before, after)
		}
	}
}

func TestDiffGitPath(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   string
		ok     bool
	}{
		{"diff --git a/plain.txt b/plain.txt", "plain.txt", true},
		{"diff --git a/spaced a b/c.txt b/spaced a b/c.txt", "spaced a b/c.txt", true},
		{`diff --git "a/tab\tname" "b/tab\tname"`, "tab\tname", true},
		{`diff --git "a/caf\303\251" "b/caf\303\251"`, "café", true},
		// A rename names two different paths and belongs to neither.
		{"diff --git a/old.txt b/new.txt", "", false},
		{"diff --git plain.txt plain.txt", "", false},
		{"diff --cc conflict.txt", "", false},
	} {
		got, ok := diffGitPath(tc.header)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("diffGitPath(%q) = %q, %v; want %q, %v", tc.header, got, ok, tc.want, tc.ok)
		}
	}
}
