package cli

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloptima/cloptima-treehouse/internal/ingest"
)

// newTestSyncer swaps the network call for a recorder so the concurrency
// behaviour can be observed without a server.
func newTestSyncer(run func()) *repoSyncer {
	s := newRepoSyncer("", "", "", "", nil, nil)
	s.syncFn = func() error {
		run()
		return nil
	}
	return s
}

// Every worktree of a repo gets its own watcher with its own debounce timer,
// and they all report the same whole-repo snapshot. Without serialization
// several full syncs ran at once, each reading git state at a different
// instant, and whichever request the server happened to finish last won --
// so an older snapshot could overwrite a newer one and pin stale state until
// the next filesystem event.
func TestRepoSyncerRunsOneSyncAtATime(t *testing.T) {
	var inFlight, maxInFlight int32
	var mu sync.Mutex

	syncer := newTestSyncer(func() {
		current := atomic.AddInt32(&inFlight, 1)
		mu.Lock()
		if current > maxInFlight {
			maxInFlight = current
		}
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
	})

	for i := 0; i < 20; i++ {
		go syncer.Trigger()
	}
	waitForIdle(t, syncer)

	mu.Lock()
	defer mu.Unlock()
	if maxInFlight > 1 {
		t.Fatalf("expected at most one sync in flight, saw %d", maxInFlight)
	}
}

// Overlapping triggers coalesce into one follow-up rather than queueing: every
// trigger asks the same question, so N pending triggers and one pending
// trigger have identical answers. One follow-up is still required -- dropping
// it would lose the change that arrived mid-sync.
func TestRepoSyncerCoalescesButNeverDropsTheLastTrigger(t *testing.T) {
	var runs int32
	started := make(chan struct{})
	release := make(chan struct{})

	syncer := newTestSyncer(func() {
		if atomic.AddInt32(&runs, 1) == 1 {
			close(started)
			<-release
		}
	})

	syncer.Trigger()
	<-started
	for i := 0; i < 10; i++ {
		syncer.Trigger()
	}
	close(release)
	waitForIdle(t, syncer)

	if got := atomic.LoadInt32(&runs); got != 2 {
		t.Fatalf("expected the first sync plus exactly one coalesced follow-up, got %d runs", got)
	}
}

func TestRepoSyncerRunsAgainAfterGoingIdle(t *testing.T) {
	var runs int32
	syncer := newTestSyncer(func() { atomic.AddInt32(&runs, 1) })

	syncer.Trigger()
	waitForIdle(t, syncer)
	syncer.Trigger()
	waitForIdle(t, syncer)

	if got := atomic.LoadInt32(&runs); got != 2 {
		t.Fatalf("expected 2 runs, got %d", got)
	}
}

func waitForIdle(t *testing.T, s *repoSyncer) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		idle := !s.running && !s.pending
		s.mu.Unlock()
		if idle {
			// Let a just-finished run settle before sampling again.
			time.Sleep(10 * time.Millisecond)
			s.mu.Lock()
			idle = !s.running && !s.pending
			s.mu.Unlock()
			if idle {
				return
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("syncer did not go idle")
}

// A snapshot's worktree list is authoritative -- the server replaces the
// stored array with it. A repo git cannot read must therefore surface as an
// error, never as an empty worktree list, which would erase a repo the user
// can still see on disk.
//
// The path has to be one that cannot exist rather than merely a non-repo
// directory: the repo wrappers point TMPDIR inside this checkout, so
// t.TempDir() sits under a real git repo and `git worktree list` there
// happily succeeds. (That is why this test's predecessor passed -- it was
// asserting on the push to a dead port that followed, not on the snapshot.)
func TestBuildSnapshotRefusesToPublishAnEmptyWorktreeList(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-a-directory")
	if _, err := buildSnapshot("laptop", testIdentity(t), missing, nil); err == nil {
		t.Fatal("expected an error rather than a snapshot to push")
	}
}

// A heartbeat over an unchanged repo must not re-upload diffs it already
// uploaded, and a repo whose content moved must not take the shortcut.
func TestCanSendLeanOnlyWhenNothingTheServerStoresMoved(t *testing.T) {
	snapshot := ingest.RepoSnapshotPayload{
		RepoName: "demo",
		Worktrees: []ingest.WorktreePayload{
			{Path: "/w/main", Branch: "main", IsDirty: true, ContentToken: "aaa"},
			{Path: "/w/feat", Branch: "feat", ContentToken: "clean"},
		},
	}

	s := newRepoSyncer("", "", "laptop", "/repo", nil, nil)
	if s.canSendLean(snapshot) {
		t.Fatal("nothing pushed yet, so there is nothing to claim is unchanged")
	}

	s.remember(snapshot)
	if !s.canSendLean(snapshot) {
		t.Fatal("an identical snapshot should go lean")
	}

	changed := snapshot
	changed.Worktrees = append([]ingest.WorktreePayload(nil), snapshot.Worktrees...)
	changed.Worktrees[0].ContentToken = "bbb"
	if s.canSendLean(changed) {
		t.Fatal("changed diff content must be pushed in full")
	}

	// A fetch moves ahead/behind without touching a file, and that still has
	// to reach the durable row.
	fetched := snapshot
	fetched.Worktrees = append([]ingest.WorktreePayload(nil), snapshot.Worktrees...)
	fetched.Worktrees[1].Behind = 3
	if s.canSendLean(fetched) {
		t.Fatal("changed ahead/behind must be pushed in full")
	}

	removed := snapshot
	removed.Worktrees = snapshot.Worktrees[:1]
	if s.canSendLean(removed) {
		t.Fatal("a removed worktree must be pushed in full")
	}
}

// fsnotify only fires on change, so a repo nobody touches stops syncing
// entirely. The heartbeat is what keeps an idle machine's last_seen_at honest
// and its cached diff state warm.
func TestWatchLoopRunsBothPeriodicJobs(t *testing.T) {
	var reconciles, syncs int32
	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		runWatchLoop(
			stop,
			2*time.Millisecond,
			2*time.Millisecond,
			0,
			func() { atomic.AddInt32(&reconciles, 1) },
			func() { atomic.AddInt32(&syncs, 1) },
		)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&reconciles) > 0 && atomic.LoadInt32(&syncs) > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(stop)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the watch loop did not stop when its stop channel closed")
	}

	if got := atomic.LoadInt32(&reconciles); got == 0 {
		t.Fatal("worktree rediscovery never ran")
	}
	if got := atomic.LoadInt32(&syncs); got == 0 {
		t.Fatal("the heartbeat never triggered a sync")
	}
}

// The heartbeat has to be well inside the server's diff cache TTL, which is
// what it exists to keep warm, and slower than the debounce so it never
// competes with an ordinary change-driven sync.
func TestHeartbeatCadenceIsSane(t *testing.T) {
	if heartbeatInterval < worktreeDiscoveryInterval {
		t.Fatalf("heartbeat (%s) should not be more frequent than worktree discovery (%s)", heartbeatInterval, worktreeDiscoveryInterval)
	}
	if heartbeatInterval > time.Hour {
		t.Fatalf("heartbeat (%s) is too slow to keep last_seen_at meaningful", heartbeatInterval)
	}
}

// TestSyncerBacksOffAfterAFailure verifies exponential backoff when a push fails,
// preventing tight retry loops against failing endpoints.
func TestSyncerBacksOffAfterAFailure(t *testing.T) {
	s := newRepoSyncer("", "", "laptop", "/repo", nil, nil)
	s.noteResult(errors.New("connection refused"))

	s.mu.Lock()
	wait := time.Until(s.notBefore)
	failures := s.consecutiveFailures
	s.mu.Unlock()

	if failures != 1 {
		t.Fatalf("consecutiveFailures = %d, want 1", failures)
	}
	if wait <= 0 || wait > syncBackoffBase {
		t.Fatalf("expected a backoff of about %v, got %v", syncBackoffBase, wait)
	}
}

// A success clears the debt immediately: the next real change must not wait
// out a backoff earned by a fault that is already over.
func TestSyncerClearsBackoffOnSuccess(t *testing.T) {
	s := newRepoSyncer("", "", "laptop", "/repo", nil, nil)
	s.noteResult(errors.New("boom"))
	s.noteResult(nil)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consecutiveFailures != 0 {
		t.Fatalf("consecutiveFailures = %d, want 0", s.consecutiveFailures)
	}
	if !s.notBefore.IsZero() {
		t.Fatalf("expected the backoff to be cleared, next attempt held until %v", s.notBefore)
	}
}

// The server knows when its own rate-limit window resets; guessing instead
// would have clients backing off on disparate schedules and colliding again.
func TestSyncerPrefersServerRetryAfter(t *testing.T) {
	s := newRepoSyncer("", "", "laptop", "/repo", nil, nil)
	s.noteResult(&ingest.PushError{StatusCode: 429, RetryAfter: 4 * time.Minute})

	s.mu.Lock()
	wait := time.Until(s.notBefore)
	s.mu.Unlock()

	// Well past the first-failure backoff, which is what proves the server's
	// instruction won rather than the local schedule.
	if wait <= syncBackoffBase {
		t.Fatalf("expected the server's 4m Retry-After to win, waiting %v", wait)
	}
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	if got := backoffFor(0); got != 0 {
		t.Fatalf("no failures must mean no wait, got %v", got)
	}
	if backoffFor(2) <= backoffFor(1) {
		t.Fatal("backoff must grow with consecutive failures")
	}
	// Capped just above the heartbeat, so the worst case still retries about
	// as often as an idle repo syncs and recovery is noticed without a restart.
	if got := backoffFor(50); got != syncBackoffMax {
		t.Fatalf("backoff must cap at %v, got %v", syncBackoffMax, got)
	}
}

// A stopped repo must not hold a goroutine parked on a six-minute timer.
func TestBackoffWaitIsInterruptedByStop(t *testing.T) {
	stop := make(chan struct{})
	s := newRepoSyncer("", "", "laptop", "/repo", nil, stop)
	s.mu.Lock()
	s.notBefore = time.Now().Add(time.Hour)
	s.mu.Unlock()

	done := make(chan bool, 1)
	go func() { done <- s.waitForBackoff() }()

	close(stop)
	select {
	case proceed := <-done:
		if proceed {
			t.Fatal("a stopped syncer must not proceed with the attempt")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitForBackoff ignored its stop channel")
	}
}

// Every watcher starts within milliseconds of the others, so without a phase
// offset a machine watching multiple repos delivers its whole heartbeat load
// in one synchronized burst.
func TestHeartbeatJitterSpreadsRepos(t *testing.T) {
	seen := map[time.Duration]bool{}
	for i := 0; i < 50; i++ {
		offset := heartbeatJitter()
		if offset < 0 || offset >= heartbeatInterval {
			t.Fatalf("offset %v must fall inside one heartbeat interval", offset)
		}
		seen[offset] = true
	}
	if len(seen) < 2 {
		t.Fatal("every repo drew the same offset; they would still burst together")
	}
}

// The offset delays only the first heartbeat. Each repo still syncs exactly
// once per interval afterwards -- the phase moves, the rate does not.
func TestWatchLoopAppliesTheOffsetOnceThenTicks(t *testing.T) {
	var syncs int32
	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		runWatchLoop(stop, time.Hour, 5*time.Millisecond, 20*time.Millisecond, func() {}, func() {
			atomic.AddInt32(&syncs, 1)
		})
	}()

	// Nothing before the offset elapses.
	time.Sleep(10 * time.Millisecond)
	if got := atomic.LoadInt32(&syncs); got != 0 {
		t.Fatalf("heartbeat fired %d times before its offset elapsed", got)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&syncs) < 3 {
		time.Sleep(time.Millisecond)
	}
	close(stop)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the watch loop did not stop when its stop channel closed")
	}
	if got := atomic.LoadInt32(&syncs); got < 3 {
		t.Fatalf("the steady heartbeat never took over after the offset, got %d syncs", got)
	}
}
