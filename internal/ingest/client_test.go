package ingest

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cloptima/cloptima-treehouse/internal/crypto"
	"github.com/cloptima/cloptima-treehouse/internal/git"
	"github.com/cloptima/cloptima-treehouse/internal/payload"
)

type recordingServer struct {
	*httptest.Server
	encoding string
	body     []byte
}

func newRecordingServer(t *testing.T) *recordingServer {
	t.Helper()
	rec := &recordingServer{}
	rec.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.encoding = r.Header.Get("Content-Encoding")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		rec.body = body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"resync_required": false}`))
	}))
	t.Cleanup(rec.Close)
	return rec
}

func testIdentity(t *testing.T) *crypto.Identity {
	t.Helper()
	identity, err := crypto.EnsureIn(nil, `{"id":"55555555-5555-4555-8555-555555555555","mck":"`+
		strings.Repeat("A", 43)+`","mtk":"`+strings.Repeat("B", 43)+`","epoch":1}`)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return identity
}

// highEntropy returns printable text gzip can only shrink by about a quarter,
// so a test about the sealed budget is actually testing the sealed budget.
// Deliberately not called "incompressible": base64 of random bytes carries 6
// bits per character, and gzip does recover some of that. Every test using it
// overshoots the budget several times over, which is what keeps that margin
// from mattering.
//
// Byte patterns are no good here: invalid UTF-8 is replaced during JSON
// encoding, and the replacement characters then compress to nothing -- a test
// written that way passes while measuring the wrong thing.
func highEntropy(t *testing.T, n int) string {
	t.Helper()
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.RawStdEncoding.EncodeToString(raw)[:n]
}

// snapshotEnvelope is the metadata half of a snapshot, which SealWorktrees
// needs so it can measure the real encoded body rather than the ciphertext
// alone.
func snapshotEnvelope() RepoSnapshotPayload {
	return RepoSnapshotPayload{MachineName: "laptop", RepoPath: "/src/app", RepoName: "app"}
}

func sealedWorktree(t *testing.T, identity *crypto.Identity, patch string) WorktreePayload {
	t.Helper()
	wt, err := BuildWorktreePayload(identity, "/src/app",
		&git.WorktreeStatus{Path: "/src/app", Branch: "main", IsDirty: true},
		[]git.FileChange{{Path: "main.ts", StatLine: "+200 -0", Patch: patch}})
	if err != nil {
		t.Fatalf("build worktree: %v", err)
	}
	return wt
}

// Nothing is compressed on the wire any more: the body already carries
// gzipped-then-sealed bytes, and sealed bytes do not compress.
func TestPushSendsUncompressed(t *testing.T) {
	rec := newRecordingServer(t)
	identity := testIdentity(t)

	snapshot := RepoSnapshotPayload{
		MachineName: "laptop",
		RepoPath:    "/src/app",
		RepoName:    "app",
		Worktrees:   []WorktreePayload{sealedWorktree(t, identity, strings.Repeat("+console.log('hello world');\n", 200))},
	}

	if _, err := Push(rec.URL, "token-123", snapshot); err != nil {
		t.Fatalf("Push failed: %v", err)
	}
	if rec.encoding != "" {
		t.Fatalf("expected no Content-Encoding, got %q", rec.encoding)
	}

	var decoded RepoSnapshotPayload
	if err := json.Unmarshal(rec.body, &decoded); err != nil {
		t.Fatalf("body is not plain JSON: %v", err)
	}
	if decoded.MachineName != "laptop" || decoded.Worktrees[0].SealedDiff == nil {
		t.Fatalf("sealed diff did not survive the round trip: %+v", decoded.Worktrees[0])
	}
}

// The guarantee, checked at the only place it can be checked end to end: what
// actually goes out on the socket must not contain the source.
func TestPushedBodyCarriesNoPlaintext(t *testing.T) {
	rec := newRecordingServer(t)
	identity := testIdentity(t)
	const secret = "SECRET_SYMBOL_NAME"

	snapshot := RepoSnapshotPayload{
		MachineName: "laptop",
		RepoPath:    "/src/app",
		RepoName:    "app",
		Worktrees:   []WorktreePayload{sealedWorktree(t, identity, "+const "+secret+" = 1;\n")},
	}

	if _, err := Push(rec.URL, "token-123", snapshot); err != nil {
		t.Fatalf("Push failed: %v", err)
	}
	if bytes.Contains(rec.body, []byte(secret)) {
		t.Fatal("the request body contains the patch text")
	}
	// The metadata the product runs on is deliberately still readable.
	if !bytes.Contains(rec.body, []byte("/src/app")) {
		t.Fatal("paths must stay in the clear -- the overview and notifications need them")
	}
}

// A heartbeat drops the sealed bodies but keeps structure, magnitude and the
// content tokens, which is what makes an idle repo cost a few hundred bytes.
func TestLeanKeepsMetadataAndDropsSealedBodies(t *testing.T) {
	identity := testIdentity(t)
	full := RepoSnapshotPayload{
		MachineName: "laptop",
		RepoPath:    "/src/app",
		RepoName:    "app",
		Grants:      map[string]string{"reader-1": "wrapped"},
		Worktrees:   []WorktreePayload{sealedWorktree(t, identity, "+x\n")},
	}

	lean := full.Lean()
	if !lean.DiffsOmitted {
		t.Fatal("a lean snapshot must say so")
	}
	if lean.Worktrees[0].SealedDiff != nil {
		t.Fatal("lean must carry no sealed bodies")
	}
	if lean.Grants != nil {
		t.Fatal("grants belong to the push that produced them")
	}
	wt := lean.Worktrees[0]
	if wt.ContentToken == "" || wt.ChangedFiles != 1 || wt.Additions != 200 {
		t.Fatalf("lean must keep what the server compares and renders: %+v", wt)
	}
	// The original must be untouched -- Lean copies.
	if full.Worktrees[0].SealedDiff == nil {
		t.Fatal("Lean must not strip the snapshot it was called on")
	}
}

// Magnitude is sent explicitly in the clear alongside the sealed diff.
func TestWorktreePayloadReportsMagnitudeInTheClear(t *testing.T) {
	identity := testIdentity(t)
	wt, err := BuildWorktreePayload(identity, "/src/app",
		&git.WorktreeStatus{Path: "/src/app", IsDirty: true},
		[]git.FileChange{
			{Path: "a.go", StatLine: "+10 -2", Patch: "@@\n"},
			{Path: "b.go", StatLine: "+5 -1", Patch: "@@\n"},
		})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if wt.Additions != 15 || wt.Deletions != 3 || wt.ChangedFiles != 2 {
		t.Fatalf("expected +15 -3 across 2, got +%d -%d across %d", wt.Additions, wt.Deletions, wt.ChangedFiles)
	}
}

// A clean worktree seals nothing but must still carry a token, or the server
// reads it as "unknown", never compares it, and a worktree going clean looks
// like nothing happened.
func TestCleanWorktreeSealsNothingButStillFingerprints(t *testing.T) {
	identity := testIdentity(t)
	wt, err := BuildWorktreePayload(identity, "/src/app",
		&git.WorktreeStatus{Path: "/src/app"}, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if wt.SealedDiff != nil {
		t.Fatal("a clean worktree has nothing to seal")
	}
	if wt.ContentToken == "" {
		t.Fatal("a clean worktree still needs a token")
	}
	if wt.ChangedFiles != 0 {
		t.Fatalf("expected no changed files, got %d", wt.ChangedFiles)
	}
}

// The sealed total is what the server bounds, so the daemon shrinks against
// the artifact it will actually be measured on -- and must never ship a
// payload the server is going to reject.
func TestSealWorktreesShrinksUntilTheSealedTotalFits(t *testing.T) {
	identity := testIdentity(t)
	statuses := []*git.WorktreeStatus{{Path: "/src/app", IsDirty: true}}
	limited := []payload.WorktreeChanges{{Path: "/src/app", Changes: []git.FileChange{
		{Path: "huge.bin", StatLine: "+1 -0", Patch: highEntropy(t, 2*payload.MaxSealedBytes)},
		{Path: "also-huge.bin", StatLine: "+1 -0", Patch: highEntropy(t, payload.MaxSealedBytes)},
		{Path: "small.go", StatLine: "+1 -0", Patch: "@@ -1 +1 @@\n+x\n"},
	}}}

	out, err := SealWorktrees(identity, "/src/app", statuses, limited, snapshotEnvelope())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if got := out[0].SealedDiff.DecodedLen(); got > payload.MaxSealedBytes {
		t.Fatalf("sealed %d bytes, over the %d budget", got, payload.MaxSealedBytes)
	}
	// Largest-first: the small, reviewable diff is what survives.
	if limited[0].Changes[2].StatOnly {
		t.Fatal("the smallest file must survive; largest are dropped first")
	}
	if !limited[0].Changes[0].StatOnly {
		t.Fatal("the largest file must have been reduced to a stat line")
	}
}

// Under budget, nothing is dropped -- the shrink loop must not cost a file on
// an ordinary sync.
func TestSealWorktreesLeavesAnOrdinarySnapshotAlone(t *testing.T) {
	identity := testIdentity(t)
	statuses := []*git.WorktreeStatus{{Path: "/src/app", IsDirty: true}}
	limited := []payload.WorktreeChanges{{Path: "/src/app", Changes: []git.FileChange{
		{Path: "main.go", StatLine: "+3 -1", Patch: "@@ -1 +1 @@\n-old\n+new\n"},
	}}}

	out, err := SealWorktrees(identity, "/src/app", statuses, limited, snapshotEnvelope())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if limited[0].Changes[0].StatOnly {
		t.Fatal("a small snapshot must keep its patches")
	}
	if out[0].SealedDiff == nil {
		t.Fatal("expected a sealed body")
	}
}

// The budget is the whole snapshot's, not each worktree's: one POST carries
// every worktree, so a per-worktree cap would let N worktrees produce N times
// the intended size.
func TestSealedBudgetIsSharedAcrossWorktrees(t *testing.T) {
	identity := testIdentity(t)

	var statuses []*git.WorktreeStatus
	var limited []payload.WorktreeChanges
	for _, path := range []string{"/w/a", "/w/b", "/w/c"} {
		statuses = append(statuses, &git.WorktreeStatus{Path: path, IsDirty: true})
		limited = append(limited, payload.WorktreeChanges{Path: path, Changes: []git.FileChange{
			{Path: path + "/big.bin", StatLine: "+1 -0", Patch: highEntropy(t, payload.MaxSealedBytes)},
		}})
	}

	out, err := SealWorktrees(identity, "/repo", statuses, limited, snapshotEnvelope())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	total := 0
	for _, wt := range out {
		if wt.SealedDiff != nil {
			total += wt.SealedDiff.DecodedLen()
		}
	}
	if total > payload.MaxSealedBytes {
		t.Fatalf("snapshot total %d exceeds the shared budget %d", total, payload.MaxSealedBytes)
	}
}

// Shrinking has to converge in a handful of re-seals, not one per file. Each
// pass re-gzips and re-encrypts the whole snapshot, so a one-file-at-a-time
// loop over a few thousand changed files is tens of seconds of CPU on the
// user's laptop -- repeated on every three-second debounce and every
// heartbeat. This is the regression test for that, and it bounds wall time
// rather than counting passes so it fails on the behaviour that hurts.
func TestSealWorktreesConvergesWithoutRescanningPerFile(t *testing.T) {
	identity := testIdentity(t)

	// Many small high-entropy files: the shape where per-file shedding is
	// worst, because each drop removes very little of the overshoot.
	const files = 3000
	changes := make([]git.FileChange, 0, files)
	for i := 0; i < files; i++ {
		changes = append(changes, git.FileChange{
			Path:     fmt.Sprintf("src/gen/file-%04d.txt", i),
			StatLine: "+1 -0",
			Patch:    highEntropy(t, 700),
		})
	}
	statuses := []*git.WorktreeStatus{{Path: "/src/app", IsDirty: true}}
	limited := []payload.WorktreeChanges{{Path: "/src/app", Changes: changes}}

	started := time.Now()
	out, err := SealWorktrees(identity, "/src/app", statuses, limited, snapshotEnvelope())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	elapsed := time.Since(started)

	if got := out[0].SealedDiff.DecodedLen(); got > payload.MaxSealedBytes {
		t.Fatalf("sealed %d bytes, over the %d budget", got, payload.MaxSealedBytes)
	}
	// Generous by design -- this is a CPU-scaling assertion, not a benchmark.
	// Per-file shedding here took roughly a thousand full re-seals.
	if elapsed > 5*time.Second {
		t.Fatalf("shrinking took %s; it should converge in a few passes, not one per file", elapsed)
	}
	// Largest-first still holds: something survived.
	kept := 0
	for _, c := range limited[0].Changes {
		if !c.StatOnly {
			kept++
		}
	}
	if kept == 0 {
		t.Fatal("shedding overshot and dropped every diff")
	}
}

// The transport cap is a different number measuring a different thing, and it
// can bind on its own: 250 worktrees of deeply nested paths carry real weight
// in the encoded body before a single byte of diff. The spec's rule is to
// shrink against whichever binds, not to fail.
func TestSealWorktreesShrinksAgainstTheTransportCapToo(t *testing.T) {
	identity := testIdentity(t)

	// Paths near the server's 4096 limit, enough of them that the encoded body
	// exceeds the transport cap while the ciphertext alone would not.
	const worktrees = 250
	deep := strings.Repeat("/deeply-nested-directory-name", 140)
	var statuses []*git.WorktreeStatus
	var limited []payload.WorktreeChanges
	for i := 0; i < worktrees; i++ {
		path := fmt.Sprintf("%s/wt-%03d", deep, i)
		statuses = append(statuses, &git.WorktreeStatus{Path: path, IsDirty: true})
		limited = append(limited, payload.WorktreeChanges{Path: path, Changes: []git.FileChange{
			{Path: "a.go", StatLine: "+1 -0", Patch: highEntropy(t, 3000)},
		}})
	}

	out, err := SealWorktrees(identity, "/src/app", statuses, limited, snapshotEnvelope())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	envelope := snapshotEnvelope()
	envelope.Worktrees = out
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(encoded) > payload.MaxTransportBytes {
		t.Fatalf("encoded body is %d bytes, over the %d transport cap", len(encoded), payload.MaxTransportBytes)
	}
}

// The transport cap bounds the request that is actually sent, and grants are
// part of it. Measuring the snapshot before they are attached lets a body sit
// just under the cap during shrinking and go over it by the time Push runs,
// which fails the sync outright instead of shedding one more patch.
//
// The grant volume here is larger than any one response asks the daemon to
// wrap. That is deliberate: what is being asserted is whether the measurement
// counts grants at all, which is true or false independently of how many there
// are, and sizing the fixture to land inside a 20 KB band would make the test
// depend on gzip's exact output.
func TestSealWorktreesCountsGrantsInTheMeasuredBody(t *testing.T) {
	identity := testIdentity(t)

	const worktrees = 250
	deep := strings.Repeat("/deeply-nested-directory-name", 140)
	statuses := make([]*git.WorktreeStatus, 0, worktrees)
	for i := 0; i < worktrees; i++ {
		statuses = append(statuses, &git.WorktreeStatus{
			Path: fmt.Sprintf("%s/wt-%03d", deep, i), IsDirty: true,
		})
	}
	// SealWorktrees sheds in place, so each pass gets its own copy.
	freshChanges := func() []payload.WorktreeChanges {
		out := make([]payload.WorktreeChanges, 0, worktrees)
		for _, ws := range statuses {
			out = append(out, payload.WorktreeChanges{Path: ws.Path, Changes: []git.FileChange{
				{Path: "a.go", StatLine: "+1 -0", Patch: highEntropy(t, 2600)},
			}})
		}
		return out
	}

	// First, the same snapshot with no grants in the envelope -- what the
	// buggy ordering measured. It fits, which is what makes the second pass
	// meaningful: any shedding there is on the grants' account.
	bareWorktrees, err := SealWorktrees(identity, "/src/app", statuses, freshChanges(), snapshotEnvelope())
	if err != nil {
		t.Fatalf("seal without grants: %v", err)
	}
	bare := snapshotEnvelope()
	bare.Worktrees = bareWorktrees
	bareEncoded, err := json.Marshal(bare)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	headroom := payload.MaxTransportBytes - len(bareEncoded)
	if headroom <= 0 {
		t.Fatalf("fixture is already over the cap without grants (%d bytes)", len(bareEncoded))
	}

	// Enough real wraps to exceed that headroom, sized from the measurement
	// rather than guessed, so the test cannot quietly stop exercising the
	// case when compression or path lengths shift. The volume is beyond what
	// one response asks the daemon to wrap; what is being asserted is whether
	// the measurement counts grants at all, which does not depend on how many.
	reader := readerPublicKey(t)
	grants := make(map[string]string)
	for size := 0; size <= headroom; {
		id := fmt.Sprintf("reader-%04d", len(grants))
		wrap, err := crypto.WrapMachineKey(identity, id, reader)
		if err != nil {
			t.Fatalf("wrap: %v", err)
		}
		grants[id] = wrap
		size = grantBytes(t, grants)
	}

	envelope := snapshotEnvelope()
	envelope.Grants = grants
	out, err := SealWorktrees(identity, "/src/app", statuses, freshChanges(), envelope)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	envelope.Worktrees = out
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(encoded) > payload.MaxTransportBytes {
		t.Fatalf("encoded body with grants is %d bytes, over the %d transport cap",
			len(encoded), payload.MaxTransportBytes)
	}
}

// grantBytes is what the grants add to the encoded body.
func grantBytes(t *testing.T, grants map[string]string) int {
	t.Helper()
	encoded, err := json.Marshal(grants)
	if err != nil {
		t.Fatalf("encode grants: %v", err)
	}
	return len(encoded)
}

// readerPublicKey is a throwaway P-256 point in the encoding WrapMachineKey
// expects, so the grant fixtures above are real envelopes rather than
// stand-ins of a guessed size.
func readerPublicKey(t *testing.T) string {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("reader key: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
}

// PushError classifies server responses so permanent rejections and rate limits
// are handled appropriately.
func TestPushErrorClassifiesTheServersAnswer(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		body        string
		retryAfter  string
		wantCode    string
		permanent   bool
		rateLimited bool
		wantWait    time.Duration
	}{
		{
			name:      "revoked or expired credential",
			status:    http.StatusUnauthorized,
			body:      `{"error":"Authentication required"}`,
			permanent: true,
		},
		{
			name:      "plan capacity reached",
			status:    http.StatusForbidden,
			body:      `{"error":"Machine limit reached (2/2).","code":"ENTITLEMENT_LIMIT_EXCEEDED"}`,
			wantCode:  "ENTITLEMENT_LIMIT_EXCEEDED",
			permanent: true,
		},
		{
			name:      "machine bound to another member",
			status:    http.StatusForbidden,
			body:      `{"error":"Token is bound to a different machine"}`,
			permanent: true,
		},
		{
			name:        "asked to slow down",
			status:      http.StatusTooManyRequests,
			body:        `{"error":"Too many Treehouse snapshots","code":"RATE_LIMIT_EXCEEDED"}`,
			retryAfter:  "45",
			wantCode:    "RATE_LIMIT_EXCEEDED",
			rateLimited: true,
			wantWait:    45 * time.Second,
		},
		{
			// Never permanent: the server is briefly unwell, not saying no.
			name:   "server hiccup",
			status: http.StatusBadGateway,
			body:   `{"error":"Internal server error"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			_, err := Push(server.URL, "token", RepoSnapshotPayload{MachineName: "laptop", RepoPath: "/r", RepoName: "r"})

			var pushErr *PushError
			if !errors.As(err, &pushErr) {
				t.Fatalf("expected a *PushError the caller can act on, got %T: %v", err, err)
			}
			if pushErr.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", pushErr.StatusCode, tc.status)
			}
			if pushErr.Code != tc.wantCode {
				t.Fatalf("code = %q, want %q", pushErr.Code, tc.wantCode)
			}
			if pushErr.Permanent() != tc.permanent {
				t.Fatalf("Permanent() = %v, want %v", pushErr.Permanent(), tc.permanent)
			}
			if pushErr.RateLimited() != tc.rateLimited {
				t.Fatalf("RateLimited() = %v, want %v", pushErr.RateLimited(), tc.rateLimited)
			}
			if pushErr.RetryAfter != tc.wantWait {
				t.Fatalf("RetryAfter = %v, want %v", pushErr.RetryAfter, tc.wantWait)
			}
		})
	}
}

// Retry-After is the server's own instruction and is obeyed rather than
// guessed at, but it cannot take a machine's feed offline indefinitely.
func TestParseRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   time.Duration
	}{
		{"60", time.Minute},
		{" 30 ", 30 * time.Second},
		{"", 0},
		{"0", 0},
		{"-5", 0},
		// An HTTP-date is legal in the RFC but nothing on this route sends
		// one; it must read as "unset" rather than as a parse that half works.
		{"Wed, 21 Oct 2026 07:28:00 GMT", 0},
		// Capped, or a server could park this machine for an hour.
		{"99999", maxRetryAfter * time.Second},
	} {
		if got := parseRetryAfter(tc.header); got != tc.want {
			t.Fatalf("parseRetryAfter(%q) = %v, want %v", tc.header, got, tc.want)
		}
	}
}
