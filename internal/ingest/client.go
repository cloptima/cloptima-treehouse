// Package ingest pushes a repo snapshot to the server's
// /v1/treehouse/ingest endpoint.
package ingest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cloptima/cloptima-treehouse/internal/crypto"
	"github.com/cloptima/cloptima-treehouse/internal/git"
	"github.com/cloptima/cloptima-treehouse/internal/payload"
)

// FileDiffPayload and WorktreeDiffPayload are the *inside* of the sealed
// envelope, and nothing but this daemon and the reader client ever sees them. The server
// holds the ciphertext and cannot open it, so this is a private contract
// between two ends rather than a wire format.
//
// camelCase, deliberately, against the snake_case convention every other
// payload in this package follows: these field names are consumed directly by
// the web client's TreehouseDiff model after decryption, with no mapping layer
// in between. Keeping one spelling means a field added here appears there
// rather than arriving as undefined.
type FileDiffPayload struct {
	Path     string `json:"path"`
	Staged   bool   `json:"staged"`
	StatLine string `json:"statLine"`
	Patch    string `json:"patch,omitempty"`
	StatOnly bool   `json:"statOnly"`
}

type WorktreeDiffPayload struct {
	StatSummary string            `json:"statSummary"`
	Files       []FileDiffPayload `json:"files"`
}

// WorktreePayload is one worktree as the server sees it: everything the
// product runs on in the clear, and the diff itself sealed.
//
// The clear fields are not an oversight. The Live feed ranks on them, the
// settle notification's title needs them, and plan caps are counted from them
// -- metadata visibility across the organization is key. Only the patch bodies are withheld.
type WorktreePayload struct {
	Path    string `json:"path"`
	Branch  string `json:"branch,omitempty"`
	Ahead   int    `json:"ahead"`
	Behind  int    `json:"behind"`
	IsDirty bool   `json:"is_dirty"`
	// Additions, Deletions and ChangedFiles are sent explicitly so the server
	// does not need to parse diff contents. Under-reporting degrades only this
	// machine's own feed, so they are the sender's word and are not checked.
	Additions    int `json:"additions"`
	Deletions    int `json:"deletions"`
	ChangedFiles int `json:"changed_files"`
	// ContentToken fingerprints this worktree's diff under MTK. The server
	// stores it and compares the next one against it; it never recomputes or
	// interprets it. It is what lets Lean() drop the bodies from a heartbeat.
	ContentToken string `json:"content_token,omitempty"`
	// SealedDiff is the diff, encrypted. The server stores these bytes and
	// returns them; it cannot open them and nothing it does depends on their
	// contents.
	SealedDiff *crypto.SealedDiff `json:"sealed_diff,omitempty"`
}

// DiffsOmitted tells the server this snapshot carries structure and content
// tokens only. See Lean.
type RepoSnapshotPayload struct {
	// MachineInstanceID identifies this machine. The server validates it against
	// the identity bound into the access token -- so sending it is a consistency check,
	// not an assertion.
	MachineInstanceID string `json:"machine_instance_id"`
	// Grants carries wrapped machine content keys for reader keys a previous
	// response reported as pending, keyed by reader key id. It rides the
	// ingest rather than needing an endpoint or a scope of its own.
	Grants       map[string]string `json:"grants,omitempty"`
	MachineName  string            `json:"machine_name"`
	RepoPath     string            `json:"repo_path"`
	RepoName     string            `json:"repo_name"`
	DiffsOmitted bool              `json:"diffs_omitted,omitempty"`
	Worktrees    []WorktreePayload `json:"worktrees"`
}

// Response is what the server answers an ingest with. ResyncRequired means
// the lean snapshot we just sent was not enough -- the server's cache can no
// longer back our "nothing changed" claim -- and this repo must be pushed
// again in full.
type Response struct {
	ResyncRequired bool `json:"resync_required"`
	// PendingGrants lists reader keys this machine has not yet wrapped its
	// content key for. It arrives on the response to a push the daemon itself
	// made, which is not an inbound path -- connections are outbound only.
	PendingGrants []PendingGrant `json:"pending_grants,omitempty"`
}

// PendingGrant is one reader device waiting to be granted access.
type PendingGrant struct {
	ReaderKeyID string `json:"reader_key_id"`
	PublicKey   string `json:"public_key"`
}

// Lean returns a copy of this snapshot with every diff body stripped, keeping
// structure and content tokens. Sending that instead of the full payload is
// the difference between a heartbeat costing a few hundred bytes and it
// re-uploading every patch in the repo, unchanged, every five minutes --
// which for a repo with several dirty worktrees is megabytes over whatever
// connection a laptop happens to be on.
//
// Only ever used when the caller has confirmed that every worktree's token
// matches what it last successfully pushed; the server rejects the claim (via
// ResyncRequired) if its own state disagrees.
func (s RepoSnapshotPayload) Lean() RepoSnapshotPayload {
	lean := s
	lean.DiffsOmitted = true
	// Grants belong to the push that produced them; a heartbeat re-sending
	// them would be writing the same field again for no reason.
	lean.Grants = nil
	lean.Worktrees = make([]WorktreePayload, len(s.Worktrees))
	for i, wt := range s.Worktrees {
		wt.SealedDiff = nil
		lean.Worktrees[i] = wt
	}
	return lean
}

// BuildWorktreePayload assembles one worktree entry from git.Status's output,
// sealing its diff under this machine's content key.
//
// changes should already have payload.Apply run over it. Magnitude is counted
// here, from the same stat lines that go inside the sealed body.
func BuildWorktreePayload(
	identity *crypto.Identity,
	repoPath string,
	ws *git.WorktreeStatus,
	changes []git.FileChange,
) (WorktreePayload, error) {
	added, removed := 0, 0
	files := make([]FileDiffPayload, 0, len(changes))
	for _, c := range changes {
		files = append(files, FileDiffPayload{
			Path:     c.Path,
			Staged:   c.Staged,
			StatLine: c.StatLine,
			Patch:    c.Patch,
			StatOnly: c.Binary || c.StatOnly,
		})
		if !c.Binary {
			// StatLine is "+N -M" (see git.statLineFromNumstat); best-effort
			// parse for a summary count, not authoritative.
			var a, r int
			if _, err := fmt.Sscanf(c.StatLine, "+%d -%d", &a, &r); err == nil {
				added += a
				removed += r
			}
		}
	}

	out := WorktreePayload{
		Path:         ws.Path,
		Branch:       ws.Branch,
		Ahead:        ws.Ahead,
		Behind:       ws.Behind,
		IsDirty:      ws.IsDirty,
		Additions:    added,
		Deletions:    removed,
		ChangedFiles: len(files),
	}

	if len(files) == 0 {
		out.ContentToken = crypto.CleanContentToken(identity)
		return out, nil
	}

	// Marshalled once and used twice: the sealed body and the fingerprint of
	// it are taken over identical bytes, so a second encoding cannot make an
	// unchanged worktree look changed.
	body, err := crypto.MarshalDiff(WorktreeDiffPayload{
		StatSummary: fmt.Sprintf("+%d -%d across %d file(s)", added, removed, len(files)),
		Files:       files,
	})
	if err != nil {
		return out, err
	}
	sealed, err := crypto.SealDiff(identity, repoPath, ws.Path, body)
	if err != nil {
		return out, err
	}
	out.ContentToken = crypto.ContentToken(identity, body)
	out.SealedDiff = sealed
	return out, nil
}

// maxShrinkPasses bounds the seal-measure-shrink loop. Each pass re-seals the
// whole snapshot, so an unbounded loop is a CPU sink on the user's own laptop,
// on a three-second debounce. Proportional shedding converges in two or three
// passes; this is the guard against an estimate that keeps undershooting, not
// the mechanism.
const maxShrinkPasses = 8

// shrinkOvershoot is the extra fraction shed beyond the measured overshoot.
// Aiming for exactly the budget tends to land just over it and cost another
// full re-seal, which is the expensive thing here; 12% is cheaper than a pass.
const shrinkOvershoot = 112

// SealWorktrees builds every worktree payload for one snapshot and shrinks the
// diff set until the sealed artifact fits.
//
// The plaintext rules in payload.Apply have already run; they are cheap and
// they bind first in normal operation, since at 4-6x compression a 1 MiB
// sealed budget carries 4-6MB of source. This is the pass that enforces what
// the server actually measures, and it has to re-seal between drops because
// nothing about a file's plaintext size predicts how much ciphertext it adds.
//
// Two things are measured, because they are two different numbers. The sealed
// total is the product limit and binds first by design. The encoded body is a
// coarse transport guard, and it can bind on its own for a snapshot whose paths
// dominate its ciphertext -- 250 worktrees of deeply nested paths carry real
// weight before a single byte of diff.
//
// Never ship a payload the server is going to reject: that is the whole
// obligation here.
func SealWorktrees(
	identity *crypto.Identity,
	repoPath string,
	statuses []*git.WorktreeStatus,
	limited []payload.WorktreeChanges,
	envelope RepoSnapshotPayload,
) ([]WorktreePayload, error) {
	for pass := 0; ; pass++ {
		out := make([]WorktreePayload, 0, len(statuses))
		sealedBytes, plaintextBytes := 0, 0
		for i, ws := range statuses {
			wt, err := BuildWorktreePayload(identity, repoPath, ws, limited[i].Changes)
			if err != nil {
				return nil, err
			}
			if wt.SealedDiff != nil {
				sealedBytes += wt.SealedDiff.DecodedLen()
			}
			for _, c := range limited[i].Changes {
				plaintextBytes += len(c.Patch)
			}
			out = append(out, wt)
		}

		// Measuring the body means encoding it, so only do that once the
		// sealed total is already inside its own budget.
		overBy := sealedBytes - payload.MaxSealedBytes
		if overBy <= 0 {
			envelope.Worktrees = out
			encoded, err := json.Marshal(envelope)
			if err != nil {
				return nil, fmt.Errorf("encode snapshot: %w", err)
			}
			if len(encoded) <= payload.MaxTransportBytes {
				return out, nil
			}
			// Base64 is a 4/3 expansion, so shedding a byte of ciphertext
			// removes about 4/3 of a byte from the body.
			overBy = (len(encoded) - payload.MaxTransportBytes) * 3 / 4
		}

		if pass >= maxShrinkPasses {
			return nil, fmt.Errorf(
				"sealed snapshot for %s did not fit after %d shrink passes (%d sealed bytes)",
				repoPath, maxShrinkPasses, sealedBytes)
		}

		// Convert a ciphertext overshoot into a plaintext target using the
		// compression ratio just measured, so one pass sheds roughly what is
		// needed instead of one file. Dropping a file at a time would make
		// this quadratic in the number of changed files, and each pass costs a
		// full re-gzip and re-encrypt of the whole snapshot.
		wantPlaintext := overBy
		if sealedBytes > 0 && plaintextBytes > 0 {
			wantPlaintext = overBy * plaintextBytes / sealedBytes
		}
		wantPlaintext = wantPlaintext * shrinkOvershoot / 100

		if payload.DropLargestPatches(limited, wantPlaintext) == 0 {
			// Every patch is already a stat line and it still does not fit.
			// Refusing beats pushing something the server will reject, and the
			// log names the repo so it is diagnosable rather than looking like
			// a silent stall.
			return nil, fmt.Errorf(
				"sealed snapshot for %s is %d bytes with every diff already reduced to stat lines, over the %d limit",
				repoPath, sealedBytes, payload.MaxSealedBytes)
		}
	}
}

// Push POSTs one repo's snapshot. apiGatewayURL has no trailing slash
// (e.g. https://api.cloptima.ai).
//
// No gzip on the wire. What this carries is already compressed and then sealed,
// and sealed bytes are indistinguishable from random -- compressing them would
// spend CPU to make the body slightly larger.
func Push(apiGatewayURL, token string, snapshot RepoSnapshotPayload) (Response, error) {
	var result Response
	body, err := json.Marshal(snapshot)
	if err != nil {
		return result, fmt.Errorf("encode snapshot: %w", err)
	}

	// The decoded sealed check in SealWorktrees is what actually bounds a
	// snapshot; this is the coarse transport guard, and it should never be the
	// one that fires. If it does, something built a payload that skipped the
	// sealing loop.
	if len(body) > payload.MaxTransportBytes {
		return result, fmt.Errorf("snapshot body (%d bytes) exceeds the %d byte transport limit",
			len(body), payload.MaxTransportBytes)
	}

	req, err := http.NewRequest(http.MethodPost, apiGatewayURL+"/v1/treehouse/ingest", bytes.NewReader(body))
	if err != nil {
		return result, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return result, fmt.Errorf("push snapshot: %w", err)
	}
	defer resp.Body.Close()

	respBody, readErr := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return result, newPushError(resp, respBody)
	}
	// A response we cannot parse is not a failed push -- the snapshot landed.
	// It only costs us the resync hint, and the next heartbeat asks again.
	if readErr == nil {
		_ = json.Unmarshal(respBody, &result)
	}
	return result, nil
}

// PushError is a rejection the server actually answered with, as distinct from
// a transport failure that never reached it. It preserves the status code,
// machine-readable error code, message, and any parsed Retry-After directive.
type PushError struct {
	StatusCode int
	// Code is the machine-readable code the server sends alongside the
	// message (ENTITLEMENT_LIMIT_EXCEEDED, RATE_LIMIT_EXCEEDED). Empty for
	// answers that carry only a message.
	Code    string
	Message string
	// RetryAfter is the server's own instruction, taken from the Retry-After
	// header. Zero when it did not send one.
	RetryAfter time.Duration
}

func (e *PushError) Error() string {
	return fmt.Sprintf("push snapshot failed (%d): %s", e.StatusCode, e.Message)
}

// Permanent reports whether retrying this request unchanged can never succeed.
//
// 401 and 403 both mean the daemon is not allowed to do this: a revoked or
// expired token, a machine bound to someone else, a plan without the feature,
// a capacity limit already reached. Retrying is not merely useless, it is
// actively misleading -- it keeps the daemon looking busy while nothing lands.
//
// 429 is deliberately not permanent: it is the server asking for a pause, and
// RetryAfter says how long.
func (e *PushError) Permanent() bool {
	return e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden
}

// RateLimited reports whether the server asked this daemon to slow down.
func (e *PushError) RateLimited() bool { return e.StatusCode == http.StatusTooManyRequests }

func newPushError(resp *http.Response, body []byte) *PushError {
	err := &PushError{
		StatusCode: resp.StatusCode,
		Message:    errorMessage(body),
		RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
	}
	var payload struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(body, &payload) == nil {
		err.Code = payload.Code
	}
	return err
}

// parseRetryAfter reads delta-seconds from the Retry-After header.
func parseRetryAfter(value string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds <= 0 {
		return 0
	}
	if seconds > maxRetryAfter {
		seconds = maxRetryAfter
	}
	return time.Duration(seconds) * time.Second
}

// maxRetryAfter caps what the daemon will honour, in seconds. A server that
// asked for an hour would otherwise take a machine's whole feed offline until
// someone restarted it; the heartbeat is five minutes, so anything past a few
// of those is better spent retrying and failing visibly.
const maxRetryAfter = 900

const errorBodyTruncateLen = 200

// errorMessage turns a server error body into a short, log-friendly
// string instead of dumping the raw JSON. Server errors are always
// `{"error": "..."}`; anything else (a proxy's HTML error page, an empty
// body) falls back to a truncated raw body rather than losing it entirely.
func errorMessage(body []byte) string {
	var parsed struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil && parsed.Error != "" {
		return parsed.Error
	}
	s := string(body)
	if len(s) > errorBodyTruncateLen {
		return s[:errorBodyTruncateLen] + "…"
	}
	return s
}
