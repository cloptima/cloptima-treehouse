package payload

import (
	"strings"
	"testing"

	"github.com/cloptima/cloptima-treehouse/internal/git"
)

func change(path string, patchBytes int) git.FileChange {
	return git.FileChange{Path: path, StatLine: "+1 -0", Patch: strings.Repeat("x", patchBytes)}
}

func totalPatchBytes(worktrees []WorktreeChanges) int {
	total := 0
	for _, wt := range worktrees {
		for _, c := range wt.Changes {
			total += len(c.Patch)
		}
	}
	return total
}

func find(t *testing.T, worktrees []WorktreeChanges, worktreePath, filePath string) git.FileChange {
	t.Helper()
	for _, wt := range worktrees {
		if wt.Path != worktreePath {
			continue
		}
		for _, c := range wt.Changes {
			if c.Path == filePath {
				return c
			}
		}
	}
	t.Fatalf("no change for %s in %s", filePath, worktreePath)
	return git.FileChange{}
}

// The budget covers one whole repo snapshot, because that is what one POST
// carries and what the request-body limit applies to. Applied per
// worktree, multiple dirty worktrees would otherwise scale the payload linearly
// and exceed the limit -- in exactly the many-parallel-worktrees case this product exists for.
func TestApplyBudgetIsSharedAcrossWorktrees(t *testing.T) {
	perWorktree := (maxSnapshotDiffBytes * 3) / 4
	out := Apply([]WorktreeChanges{
		{Path: "/a", Changes: []git.FileChange{change("a/one.go", perWorktree)}},
		{Path: "/b", Changes: []git.FileChange{change("b/one.go", perWorktree)}},
		{Path: "/c", Changes: []git.FileChange{change("c/one.go", perWorktree)}},
	})

	if total := totalPatchBytes(out); total > maxSnapshotDiffBytes {
		t.Fatalf("snapshot total %d exceeds the shared budget %d", total, maxSnapshotDiffBytes)
	}
}

func TestApplyDropsLargestFirstAcrossWorktrees(t *testing.T) {
	out := Apply([]WorktreeChanges{
		{Path: "/a", Changes: []git.FileChange{change("a/huge.go", maxSnapshotDiffBytes-1000)}},
		{Path: "/b", Changes: []git.FileChange{change("b/large.go", maxSnapshotDiffBytes/2)}},
		{Path: "/c", Changes: []git.FileChange{change("c/tiny.go", 200)}},
	})

	if !find(t, out, "/a", "a/huge.go").StatOnly {
		t.Fatal("the largest file must be dropped to stat-only first")
	}
	if find(t, out, "/c", "c/tiny.go").StatOnly {
		t.Fatal("the smallest, most reviewable file must survive")
	}
}

func TestApplyExcludesGeneratedFilesAndOversizedFiles(t *testing.T) {
	out := Apply([]WorktreeChanges{{Path: "/w", Changes: []git.FileChange{
		change("package-lock.json", 10),
		change("pnpm-lock.yaml", 10),
		change("yarn.lock", 10),
		change("go.sum", 10),
		change("web/dist/app.js", 10),
		change("web/build/app.js", 10),
		change("vendor.min.js", 10),
		change("src/big.go", maxFileDiffBytes+1),
		change("src/small.go", 10),
	}}})

	for _, path := range []string{
		"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "go.sum",
		"web/dist/app.js", "web/build/app.js", "vendor.min.js", "src/big.go",
	} {
		c := find(t, out, "/w", path)
		if !c.StatOnly || c.Patch != "" {
			t.Fatalf("%s should be stat-only with no patch", path)
		}
		if c.StatLine == "" {
			t.Fatalf("%s must keep its stat line", path)
		}
	}
	if find(t, out, "/w", "src/small.go").StatOnly {
		t.Fatal("an ordinary source file must keep its patch")
	}
}

// StatOnly is set explicitly wherever a limit applies rather than inferred
// from an empty patch, because a genuinely empty diff (a mode-only change)
// also has an empty patch without having been excluded.
func TestApplyLeavesGenuinelyEmptyDiffsAlone(t *testing.T) {
	out := Apply([]WorktreeChanges{{Path: "/w", Changes: []git.FileChange{
		{Path: "src/mode-only.go", StatLine: "+0 -0", Patch: ""},
	}}})

	if find(t, out, "/w", "src/mode-only.go").StatOnly {
		t.Fatal("an empty diff is not the same as an excluded one")
	}
}

func TestApplyDoesNotMutateItsInput(t *testing.T) {
	input := []WorktreeChanges{{Path: "/w", Changes: []git.FileChange{change("package-lock.json", 64)}}}
	Apply(input)

	if input[0].Changes[0].Patch == "" || input[0].Changes[0].StatOnly {
		t.Fatal("Apply must return new slices rather than editing the caller's")
	}
}

func TestApplyPreservesBinaryFiles(t *testing.T) {
	out := Apply([]WorktreeChanges{{Path: "/w", Changes: []git.FileChange{
		{Path: "assets/logo.png", StatLine: "binary file changed", Binary: true},
	}}})

	c := find(t, out, "/w", "assets/logo.png")
	if !c.Binary || c.StatLine != "binary file changed" {
		t.Fatalf("binary marker and stat line must survive, got %+v", c)
	}
}
