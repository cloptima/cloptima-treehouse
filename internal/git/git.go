// Package git shells out to the local git binary -- native porcelain
// commands are fast, deterministic, and already what git tooling relies on.
package git

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// readOnlyGitEnv and readOnlyGitConfig keep every git call from writing the
// index. By default `git status` and `git diff` rewrite .git/index to refresh
// stat data. That writes to a repo the daemon only watches, races the user's
// own git commands for index.lock, and makes the watcher see its own write as
// a change and sync again. core.splitIndex=false keeps the throwaway index in
// diffUntrackedBatch from writing a shared index file into the git dir.
//
// The config goes in as `-c` arguments, which git merges with any
// GIT_CONFIG_COUNT or GIT_CONFIG_PARAMETERS already in the environment.
// Setting GIT_CONFIG_COUNT here would replace the user's own.
var (
	readOnlyGitEnv    = []string{"GIT_OPTIONAL_LOCKS=0"}
	readOnlyGitConfig = []string{"-c", "diff.autoRefreshIndex=false", "-c", "core.splitIndex=false"}
)

// patchArgs pins every part of the patch format that git config can change.
// patchSections reads paths back out of "diff --git" headers, so nothing may
// alter or displace them: diff.noprefix and diff.mnemonicPrefix change the
// prefixes, color.ui=always puts escape codes in front, diff.external
// replaces the patch, and diff.submodule=log prints a "Submodule" block with
// no header, which would land in the previous file's patch.
var patchArgs = []string{"--no-color", "--no-ext-diff", "--submodule=short", "--src-prefix=a/", "--dst-prefix=b/"}

type FileChange struct {
	Path     string
	Staged   bool
	StatLine string
	Patch    string
	Binary   bool
	// StatOnly is set by payload.Apply when it deliberately drops Patch
	// (excluded/oversized file). An empty Patch on its own can also mean a
	// genuinely empty diff (e.g. a mode-only change) -- callers must not
	// infer StatOnly from Patch == "" alone.
	StatOnly bool
}

type WorktreeStatus struct {
	Path    string
	Branch  string
	Ahead   int
	Behind  int
	IsDirty bool
}

type statusEntry struct {
	path       string
	staged     bool
	untracked  bool
	conflicted bool
}

// recordChangedPath appends one entry per side (staged/unstaged) that xy
// actually marks as changed -- "MM" means both, appending two entries for
// the same path.
func recordChangedPath(entries *[]statusEntry, xy, path string) {
	if xy[0] != '.' {
		*entries = append(*entries, statusEntry{path: path, staged: true})
	}
	if xy[1] != '.' {
		*entries = append(*entries, statusEntry{path: path, staged: false})
	}
}

// runGit runs git in dir and returns stdout.
func runGit(dir string, args ...string) (string, error) {
	return runGitWith(dir, nil, "", args...)
}

// runGitWith is runGit with extra environment and, when non-empty, stdin.
//
// Exit code 1 means "differences found" for `git diff`, which is the ordinary
// case here rather than a failure -- but only when nothing was written to
// stderr. `git diff --no-index` also exits 1 for real failures (an
// unresolvable pathspec, a directory where a file was expected), and treating
// every exit-1 as success turned those into an empty diff: the caller saw no
// error and recorded a file entry with no stat line and no patch. The
// exemption is also scoped to `diff`; nothing else here uses exit 1 to mean
// anything but failure.
func runGitWith(dir string, env []string, stdin string, args ...string) (string, error) {
	cmd := exec.Command("git", append(slices.Clone(readOnlyGitConfig), args...)...)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), readOnlyGitEnv...), env...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.String(), nil
	}

	subcommand := ""
	if len(args) > 0 {
		subcommand = args[0]
	}
	message := strings.TrimSpace(stderr.String())

	var exitErr *exec.ExitError
	if subcommand == "diff" && message == "" && errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return stdout.String(), nil
	}
	if message != "" {
		return "", fmt.Errorf("git %s: %s", subcommand, message)
	}
	// Keep the underlying error when git wrote nothing to stderr (a missing
	// binary, a permissions failure); returning errors.New("") here made
	// those surface as a log line with an empty reason.
	return "", fmt.Errorf("git %s: %w", subcommand, err)
}

// unquotePath reverses git's C-style path quoting. Porcelain output wraps a
// path in double quotes, with C escapes, whenever it contains a control
// character, a double quote, a backslash, or -- with core.quotePath at its
// default of true -- any non-ASCII byte. Passing the quoted form back to
// `git diff` as a pathspec matches nothing, and since that exits 0 with no
// output it silently produced a file entry with no stat line and no patch.
func unquotePath(path string) string {
	if len(path) < 2 || path[0] != '"' || path[len(path)-1] != '"' {
		return path
	}
	unquoted, err := strconv.Unquote(path)
	if err != nil {
		return path
	}
	return unquoted
}

// ListWorktrees returns every worktree path registered for the repo at
// repoPath (which may itself be any one of those worktrees).
//
// A prunable worktree is left out. Its directory was deleted without `git
// worktree remove`, and git keeps listing it until `git worktree prune`, by
// default for three months. Watching or diffing it can only fail, on every
// discovery poll and every sync.
func ListWorktrees(repoPath string) ([]string, error) {
	out, err := runGit(repoPath, "worktree", "list", "--porcelain")
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, block := range strings.Split(out, "\n\n") {
		path, prunable := "", false
		for _, line := range strings.Split(block, "\n") {
			if p, ok := strings.CutPrefix(line, "worktree "); ok {
				path = p
			}
			if line == "prunable" || strings.HasPrefix(line, "prunable ") {
				prunable = true
			}
		}
		if path != "" && !prunable {
			paths = append(paths, path)
		}
	}
	return paths, nil
}

// CommonDir returns the absolute git directory that a repo's worktrees
// share, where linked worktrees are registered.
func CommonDir(repoPath string) (string, error) {
	out, err := runGit(repoPath, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// WorktreesStamp changes whenever a linked worktree may have been added,
// removed, moved, or deleted from disk. It covers the mtime of
// <commonDir>/worktrees, the mtime of each registration's gitdir file
// (`git worktree move` rewrites only that file), and whether the .git file
// that gitdir names still exists. That is a few stats and small reads per
// poll, where `git worktree list` is a process.
func WorktreesStamp(commonDir string) string {
	dir := filepath.Join(commonDir, "worktrees")
	info, err := os.Stat(dir)
	if err != nil {
		return "none"
	}
	var stamp strings.Builder
	fmt.Fprint(&stamp, info.ModTime().UnixNano())
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		gitdir := filepath.Join(dir, e.Name(), "gitdir")
		info, err := os.Stat(gitdir)
		if err != nil {
			fmt.Fprintf(&stamp, "|%s", e.Name())
			continue
		}
		target, _ := os.ReadFile(gitdir)
		dotGit := strings.TrimSpace(string(target))
		if !filepath.IsAbs(dotGit) {
			dotGit = filepath.Join(dir, e.Name(), dotGit)
		}
		_, statErr := os.Stat(dotGit)
		fmt.Fprintf(&stamp, "|%s:%d:%t", e.Name(), info.ModTime().UnixNano(), statErr == nil)
	}
	return stamp.String()
}

// status parses `git status --porcelain=v2 --branch --untracked-files=all`:
// branch/ahead/behind, plus one statusEntry per (path, staged-or-not)
// combination that actually changed -- a path with both a staged and a further
// unstaged edit ("MM") yields two entries so they are tracked separately.
func status(worktreePath string) (*WorktreeStatus, []statusEntry, error) {
	// --untracked-files=all is required, not cosmetic: the default (`normal`)
	// collapses an untracked directory into a single "? dir/" entry, so a
	// brand new feature folder -- the most common shape of agent-generated
	// work -- reported one unusable pseudo-entry and hid every file in it.
	out, err := runGit(worktreePath, "status", "--porcelain=v2", "--branch", "--untracked-files=all")
	if err != nil {
		return nil, nil, err
	}

	ws := &WorktreeStatus{Path: worktreePath}
	var entries []statusEntry
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "# branch.head "):
			ws.Branch = strings.TrimPrefix(line, "# branch.head ")
		case strings.HasPrefix(line, "# branch.ab "):
			for _, f := range strings.Fields(strings.TrimPrefix(line, "# branch.ab ")) {
				n, convErr := strconv.Atoi(strings.TrimLeft(f, "+-"))
				if convErr != nil {
					continue
				}
				if strings.HasPrefix(f, "+") {
					ws.Ahead = n
				} else if strings.HasPrefix(f, "-") {
					ws.Behind = n
				}
			}
		case strings.HasPrefix(line, "1 "):
			// "1 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <path>" -- 9 fields.
			fields := strings.SplitN(line, " ", 9)
			if len(fields) < 9 {
				continue
			}
			recordChangedPath(&entries, fields[1], unquotePath(fields[8]))
			ws.IsDirty = true
		case strings.HasPrefix(line, "2 "):
			// "2 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <score> <path><TAB><origPath>"
			// -- one extra <score> field before the path pair compared to "1 ",
			// so this needs its own split width rather than sharing "1"'s.
			fields := strings.SplitN(line, " ", 10)
			if len(fields) < 10 {
				continue
			}
			path := fields[9]
			// The rename pair is separated by a literal tab. A quoted path
			// carries an escaped "\t" (two characters), never a real tab, so
			// splitting on the raw byte is safe before unquoting.
			if idx := strings.Index(path, "\t"); idx >= 0 {
				path = path[:idx]
			}
			recordChangedPath(&entries, fields[1], unquotePath(path))
			ws.IsDirty = true
		case strings.HasPrefix(line, "? "):
			entries = append(entries, statusEntry{path: unquotePath(strings.TrimPrefix(line, "? ")), untracked: true})
			ws.IsDirty = true
		case strings.HasPrefix(line, "u "):
			// "u <XY> <sub> <m1> <m2> <m3> <mW> <h1> <h2> <h3> <path>" -- an
			// unmerged (conflicted) path. XY's two chars are never "." here
			// (e.g. "UU", "AA", "DD"), so this is always both staged and
			// unstaged at once -- but there is no single "other side" for a
			// two-way diff against a 3-way conflict, so this is recorded
			// separately (see Status(), which reports it stat-only) rather
			// than trying to shoehorn it through recordChangedPath.
			fields := strings.SplitN(line, " ", 11)
			if len(fields) < 11 {
				continue
			}
			entries = append(entries, statusEntry{path: unquotePath(fields[10]), conflicted: true})
			ws.IsDirty = true
		}
	}
	return ws, entries, nil
}

// numstatBinary reports whether `git diff --numstat` marked path as binary
// ("-\t-\tpath") -- binary content is never patched, only stat-lined.
func numstatIsBinary(numstat string) bool {
	return strings.HasPrefix(strings.TrimSpace(numstat), "-\t-\t")
}

func statLineFromNumstat(numstat string) string {
	fields := strings.SplitN(strings.TrimSpace(numstat), "\t", 3)
	if len(fields) < 2 {
		return ""
	}
	if fields[0] == "-" || fields[1] == "-" {
		return "binary file changed"
	}
	return "+" + fields[0] + " -" + fields[1]
}

// fileDiff is one path's numstat record and patch text.
type fileDiff struct {
	numstat string
	patch   string
}

// diffTracked returns every changed tracked path on one side -- the index
// against HEAD when staged, the working tree against the index otherwise --
// from one git call. One call per changed file cost hundreds of process
// spawns per sync on a busy worktree.
//
// --no-renames keeps both halves of a rename under their own paths, which is
// what the per-path lookup in Status expects. Conflicted paths are excluded:
// git prints their combined diff ahead of the numstat records, which breaks
// the split below, and Status reports them stat-only anyway.
func diffTracked(worktreePath string, staged bool, conflicted []string) (map[string]fileDiff, error) {
	args := []string{"diff"}
	if staged {
		args = append(args, "--staged")
	}
	args = append(args, "--no-renames", "--numstat", "--patch", "-z")
	args = append(args, patchArgs...)
	args = append(args, "--")
	for _, path := range conflicted {
		args = append(args, ":(exclude,literal)"+path)
	}
	out, err := runGit(worktreePath, args...)
	if err != nil {
		return nil, err
	}
	return splitNumstatPatch(out), nil
}

// diffUntrackedBatch diffs untracked files in one `git diff` call. Each file
// goes into a throwaway index as intent-to-add, and git diffs that as a new
// file, with the same bytes `diff --no-index` against /dev/null prints. One
// --no-index call per file cost one spawn per new file on every sync.
//
// `add -N` writes the empty blob, so it gets a throwaway object directory:
// the daemon never writes to a repo it watches. The diff reads no object.
// A file that vanishes after `git status` fails the whole `add`.
func diffUntrackedBatch(worktreePath string, paths []string) (map[string]fileDiff, error) {
	tmp, err := os.MkdirTemp("", "treehouse-untracked-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	objects := filepath.Join(tmp, "objects")
	if err := os.Mkdir(objects, 0o700); err != nil {
		return nil, err
	}
	index := "GIT_INDEX_FILE=" + filepath.Join(tmp, "index")

	addEnv := []string{index, "GIT_OBJECT_DIRECTORY=" + objects, "GIT_LITERAL_PATHSPECS=1"}
	stdin := strings.Join(paths, "\x00")
	if _, err := runGitWith(worktreePath, addEnv, stdin, "add", "--intent-to-add", "--pathspec-from-file=-", "--pathspec-file-nul"); err != nil {
		return nil, err
	}
	args := append([]string{"diff", "--no-renames", "--numstat", "--patch", "-z"}, patchArgs...)
	out, err := runGitWith(worktreePath, []string{index}, "", args...)
	if err != nil {
		return nil, err
	}
	return splitNumstatPatch(out), nil
}

// splitNumstatPatch maps each path in `git diff --numstat --patch -z` output
// to its numstat record and patch. With -z, the NUL-terminated numstat
// records come first, then an empty record as the separator, then the patch.
// A record is never empty, so the first double NUL is the separator.
func splitNumstatPatch(out string) map[string]fileDiff {
	records, patch, _ := strings.Cut(out, "\x00\x00")
	diffs := make(map[string]fileDiff)
	for _, record := range strings.Split(records, "\x00") {
		fields := strings.SplitN(record, "\t", 3)
		if len(fields) < 3 {
			continue
		}
		diffs[fields[2]] = fileDiff{numstat: record}
	}
	for path, section := range patchSections(patch) {
		d := diffs[path]
		d.patch = section
		diffs[path] = d
	}
	return diffs
}

// diffUntracked diffs one untracked file against /dev/null. Status uses it
// for every untracked file when diffUntrackedBatch fails. Without -z the
// numstat line C-quotes its path, so the first blank line is always the
// separator.
func diffUntracked(worktreePath, path string) (fileDiff, error) {
	args := append([]string{"diff", "--no-index", "--numstat", "--patch"}, patchArgs...)
	out, err := runGit(worktreePath, append(args, "--", "/dev/null", path)...)
	if err != nil {
		return fileDiff{}, err
	}
	numstat, patch, _ := strings.Cut(out, "\n\n")
	return fileDiff{numstat: numstat, patch: patch}, nil
}

// patchSections splits a multi-file patch into each path's "diff --git"
// sections. A typechange is a deletion plus a creation, so one path can own
// two sections. A section that names no path ("* Unmerged path") is dropped.
func patchSections(patch string) map[string]string {
	sections := make(map[string]string)
	path, start := "", 0
	for i := 0; i < len(patch); {
		end := len(patch)
		if nl := strings.IndexByte(patch[i:], '\n'); nl >= 0 {
			end = i + nl + 1
		}
		line := patch[i:end]
		if strings.HasPrefix(line, "diff --git ") || strings.HasPrefix(line, "* Unmerged path ") {
			if path != "" {
				sections[path] += patch[start:i]
			}
			path, _ = diffGitPath(strings.TrimSuffix(line, "\n"))
			start = i
		}
		i = end
	}
	if path != "" {
		sections[path] += patch[start:]
	}
	return sections
}

// diffGitPath reads the path from a "diff --git a/<path> b/<path>" header.
// With --no-renames both sides name the same path, and patchArgs gives
// both sides a two-byte prefix, so the header splits into two equal halves
// even when the path has spaces or is C-quoted.
func diffGitPath(header string) (string, bool) {
	rest, ok := strings.CutPrefix(header, "diff --git ")
	half := len(rest) / 2
	if !ok || len(rest)%2 == 0 || rest[half] != ' ' {
		return "", false
	}
	src, dst := unquotePath(rest[:half]), unquotePath(rest[half+1:])
	path, ok := strings.CutPrefix(src, "a/")
	if !ok || dst != "b/"+path {
		return "", false
	}
	return path, true
}

// Status returns the worktree's branch/ahead/behind/dirty state plus one
// FileChange per changed path (staged and unstaged tracked separately),
// with patch text already attached. Callers apply payload limits before uploading.
func Status(worktreePath string) (*WorktreeStatus, []FileChange, error) {
	ws, entries, err := status(worktreePath)
	if err != nil {
		return nil, nil, err
	}

	var conflicted, untracked []string
	var wantStaged, wantUnstaged bool
	for _, e := range entries {
		switch {
		case e.conflicted:
			conflicted = append(conflicted, e.path)
		case e.untracked:
			if !strings.HasSuffix(e.path, "/") {
				untracked = append(untracked, e.path)
			}
		case e.staged:
			wantStaged = true
		default:
			wantUnstaged = true
		}
	}
	var staged, unstaged map[string]fileDiff
	var stagedErr, unstagedErr error
	if wantStaged {
		staged, stagedErr = diffTracked(worktreePath, true, conflicted)
	}
	if wantUnstaged {
		unstaged, unstagedErr = diffTracked(worktreePath, false, conflicted)
	}
	var newFiles map[string]fileDiff
	if len(untracked) > 0 {
		if newFiles, err = diffUntrackedBatch(worktreePath, untracked); err != nil {
			log.Printf("treehouse: batched untracked diff failed in %s, diffing per file: %v", worktreePath, err)
		}
	}

	changes := make([]FileChange, 0, len(entries))
	for _, e := range entries {
		if e.conflicted {
			// A merge conflict has three sides (ours/theirs/base), not the
			// two a normal `git diff` compares -- report it stat-only
			// rather than picking an arbitrary side to diff against.
			changes = append(changes, FileChange{Path: e.path, StatLine: "conflict", StatOnly: true})
			continue
		}
		if e.untracked && strings.HasSuffix(e.path, "/") {
			// A nested repository. `diff --no-index` against a directory
			// always fails, so skip the process and its log line.
			changes = append(changes, FileChange{Path: e.path, StatLine: "diff unavailable", StatOnly: true})
			continue
		}
		var d fileDiff
		var diffErr error
		switch {
		case e.untracked:
			var batched bool
			if d, batched = newFiles[e.path]; !batched {
				d, diffErr = diffUntracked(worktreePath, e.path)
			}
		case e.staged:
			d, diffErr = staged[e.path], stagedErr
		default:
			d, diffErr = unstaged[e.path], unstagedErr
		}
		if diffErr != nil {
			// git status saw this path change, so dropping it entirely would
			// under-report the worktree. Report it stat-only with the reason
			// instead of vanishing it.
			log.Printf("treehouse: diff failed for %s in %s: %v", e.path, worktreePath, diffErr)
			changes = append(changes, FileChange{
				Path:     e.path,
				Staged:   e.staged,
				StatLine: "diff unavailable",
				StatOnly: true,
			})
			continue
		}
		binary := numstatIsBinary(d.numstat)
		patch := d.patch
		if binary {
			patch = ""
		}
		changes = append(changes, FileChange{
			Path:     e.path,
			Staged:   e.staged,
			StatLine: statLineFromNumstat(d.numstat),
			Patch:    patch,
			Binary:   binary,
		})
	}
	return ws, changes, nil
}
