// Package git shells out to the local git binary -- native porcelain
// commands are fast, deterministic, and already what git tooling relies on.
package git

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
)

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
//
// Exit code 1 means "differences found" for `git diff`, which is the ordinary
// case here rather than a failure -- but only when nothing was written to
// stderr. `git diff --no-index` also exits 1 for real failures (an
// unresolvable pathspec, a directory where a file was expected), and treating
// every exit-1 as success turned those into an empty diff: the caller saw no
// error and recorded a file entry with no stat line and no patch. The
// exemption is also scoped to `diff`; nothing else here uses exit 1 to mean
// anything but failure.
func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
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
func ListWorktrees(repoPath string) ([]string, error) {
	out, err := runGit(repoPath, "worktree", "list", "--porcelain")
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, line := range strings.Split(out, "\n") {
		if p, ok := strings.CutPrefix(line, "worktree "); ok {
			paths = append(paths, p)
		}
	}
	return paths, nil
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

// literalPathspec disables git's pathspec glob interpretation for one path.
// Without it a filename containing "*", "?", or "[" is matched as a pattern
// rather than as itself, so the diff for that file comes back empty.
// `--no-index` takes real filesystem paths rather than pathspecs, so it does
// not use this.
func literalPathspec(path string) string {
	return ":(literal)" + path
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

// Status returns the worktree's branch/ahead/behind/dirty state plus one
// FileChange per changed path (staged and unstaged tracked separately),
// with patch text already attached. Callers apply payload limits before uploading.
func Status(worktreePath string) (*WorktreeStatus, []FileChange, error) {
	ws, entries, err := status(worktreePath)
	if err != nil {
		return nil, nil, err
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
		var numstat, patch string
		var diffErr error
		switch {
		case e.untracked:
			numstat, diffErr = runGit(worktreePath, "diff", "--no-index", "--numstat", "--", "/dev/null", e.path)
		case e.staged:
			numstat, diffErr = runGit(worktreePath, "diff", "--staged", "--numstat", "--", literalPathspec(e.path))
		default:
			numstat, diffErr = runGit(worktreePath, "diff", "--numstat", "--", literalPathspec(e.path))
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
		binary := numstatIsBinary(numstat)
		statLine := statLineFromNumstat(numstat)
		if !binary {
			switch {
			case e.untracked:
				patch, _ = runGit(worktreePath, "diff", "--no-index", "--", "/dev/null", e.path)
			case e.staged:
				patch, _ = runGit(worktreePath, "diff", "--staged", "--", literalPathspec(e.path))
			default:
				patch, _ = runGit(worktreePath, "diff", "--", literalPathspec(e.path))
			}
		}
		changes = append(changes, FileChange{
			Path:     e.path,
			Staged:   e.staged,
			StatLine: statLine,
			Patch:    patch,
			Binary:   binary,
		})
	}
	return ws, changes, nil
}
