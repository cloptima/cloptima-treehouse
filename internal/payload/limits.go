// Package payload enforces payload limits client-side, before anything crosses
// the network -- the backend applies the same limits again as a backstop, but
// the point of doing it here is to never even send the bytes.
package payload

import (
	"path/filepath"
	"regexp"
	"sort"

	"github.com/cloptima/cloptima-treehouse/internal/git"
)

// MaxSealedBytes is the authoritative limit once diffs are sealed: the
// total decoded ciphertext one ingest may carry, summed across every worktree
// in it.
//
// It exists because the server can no longer see plaintext and can only
// measure the artifact it actually stores. Translating the old 2MB plaintext
// cap onto ciphertext would have been a large loosening rather than a
// like-for-like port -- diff text gzips at roughly 4-6x, so a 2MB sealed cap
// would admit 8-12MB of source.
//
// This limit matches the server-side ceiling; this package shrinks the snapshot
// until it fits so it never ships a payload the server will reject.
const MaxSealedBytes = 1024 * 1024

// MaxTransportBytes is a coarse guard on the HTTP body, and a different number
// measuring a different thing. Ciphertext travels base64url inside JSON, a 4/3
// expansion, so a payload exactly at MaxSealedBytes is about 1.33 MiB on the
// wire before a single field name or path. Setting the two equal would reject
// a payload that is exactly at budget -- and the shrink loop would then keep
// cutting until the *encoded* form fit, quietly making the real ceiling about
// 750 KiB. This never binds first, because the decoded check does.
const MaxTransportBytes = 2 * 1024 * 1024

const (
	maxFileDiffBytes = 200 * 1024
	// maxSnapshotDiffBytes is the budget for one whole repo snapshot, shared
	// across every worktree in it -- see Apply.
	maxSnapshotDiffBytes = 2 * 1024 * 1024
)

var excludedFilePattern = regexp.MustCompile(`(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|go\.sum)$|\.min\.js$|(^|/)(dist|build)/`)

// WorktreeChanges is one worktree's changes within a snapshot. Apply needs the
// whole snapshot at once because the total-size budget is shared across every
// worktree in it.
type WorktreeChanges struct {
	Path    string
	Changes []git.FileChange
}

// Apply caps individual and total diff size, excluding known
// generated/lockfile paths regardless of size. It mutates nothing --
// git.FileChange is returned by value from git.Status, so this returns new
// slices. StatOnly is set explicitly wherever a limit applies, rather than
// inferred from an empty Patch, since a genuinely empty diff (e.g. a
// mode-only change) also has an empty Patch without being excluded.
//
// maxSnapshotDiffBytes is a budget for the whole snapshot, not for each
// worktree. One POST carries every worktree in a repo and the server's
// request-body limit applies to that whole body, so a per-worktree cap let N
// worktrees produce N times the intended size -- and a repo with enough
// parallel dirty worktrees, which is exactly what this product is for, would
// exceed the server limit and stop syncing entirely.
func Apply(worktrees []WorktreeChanges) []WorktreeChanges {
	// position identifies one file across the flattened snapshot so the
	// largest-first pass ranks files across worktrees, not just within one.
	type position struct {
		worktree int
		file     int
	}

	out := make([]WorktreeChanges, len(worktrees))
	var order []position
	total := 0

	for i, wt := range worktrees {
		out[i] = WorktreeChanges{Path: wt.Path, Changes: make([]git.FileChange, len(wt.Changes))}
		copy(out[i].Changes, wt.Changes)
		for j := range out[i].Changes {
			c := &out[i].Changes[j]
			if !c.Binary && !c.StatOnly &&
				(excludedFilePattern.MatchString(filepath.ToSlash(c.Path)) || len(c.Patch) > maxFileDiffBytes) {
				c.Patch = ""
				c.StatOnly = true
			}
			total += len(c.Patch)
			order = append(order, position{worktree: i, file: j})
		}
	}

	if total > maxSnapshotDiffBytes {
		sort.SliceStable(order, func(a, b int) bool {
			return len(out[order[a].worktree].Changes[order[a].file].Patch) >
				len(out[order[b].worktree].Changes[order[b].file].Patch)
		})
		for _, pos := range order {
			if total <= maxSnapshotDiffBytes {
				break
			}
			c := &out[pos.worktree].Changes[pos.file]
			if c.StatOnly {
				continue
			}
			total -= len(c.Patch)
			c.Patch = ""
			c.StatOnly = true
		}
	}

	return out
}

// DropLargestPatches turns the largest remaining patches into stat lines until
// at least wantBytes of plaintext have been shed, and reports how much it
// actually dropped. Zero means there was nothing left to drop.
//
// Largest-first because the small, reviewable diffs are what someone opens
// their phone to read; never mid-hunk, because half a hunk is worse than a stat
// line.
//
// It sheds a requested amount rather than one file per call for a reason worth
// stating: the caller has to re-seal the whole snapshot to learn the new size,
// so a one-file-per-call API makes shrinking quadratic in the number of files.
// A repo with a few thousand incompressible changes would then spend tens of
// seconds of CPU re-gzipping and re-encrypting the same megabytes on every
// sync -- and this runs on someone's laptop, on a 3-second debounce.
//
// The caller converts a ciphertext overshoot into a plaintext target using the
// compression ratio it just measured. That estimate does not have to be right,
// only roughly right: the loop re-measures and asks again.
//
// Mutates in place. The slices it is given already came from Apply, which
// copies.
func DropLargestPatches(worktrees []WorktreeChanges, wantBytes int) int {
	// Rank every droppable file once, largest first, then walk the ranking.
	// Re-scanning per file would put the quadratic cost back in a different
	// place.
	type position struct{ worktree, file int }
	var order []position
	for i := range worktrees {
		for j := range worktrees[i].Changes {
			c := &worktrees[i].Changes[j]
			if c.StatOnly || c.Patch == "" {
				continue
			}
			order = append(order, position{worktree: i, file: j})
		}
	}
	sort.SliceStable(order, func(a, b int) bool {
		return len(worktrees[order[a].worktree].Changes[order[a].file].Patch) >
			len(worktrees[order[b].worktree].Changes[order[b].file].Patch)
	})

	dropped := 0
	for _, pos := range order {
		if dropped >= wantBytes {
			break
		}
		c := &worktrees[pos.worktree].Changes[pos.file]
		dropped += len(c.Patch)
		c.Patch = ""
		c.StatOnly = true
	}
	return dropped
}
