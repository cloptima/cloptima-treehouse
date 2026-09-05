package cli

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloptima/cloptima-treehouse/internal/crypto"
	"github.com/cloptima/cloptima-treehouse/internal/ingest"
)

// Machine identity is generated before login and threaded to every syncer.
// Most of these tests exercise neither pushing nor wrapping, so they pass none;
// testIdentity is for the ones that reach the sealing path.
const testInstanceID = "55555555-5555-5555-5555-555555555555"

func testIdentity(t *testing.T) *crypto.Identity {
	t.Helper()
	identity, err := crypto.EnsureIn(nil, `{"id":"`+testInstanceID+`","mck":"`+
		strings.Repeat("A", 43)+`","mtk":"`+strings.Repeat("B", 43)+`","epoch":1}`)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return identity
}

// recordingController stands in for the tray so the state's controller
// interactions can be observed. Its own fields are mutex-guarded because the
// tray calls into a controller from whichever goroutine handled the click.
type recordingController struct {
	mu            sync.Mutex
	statuses      []string
	repos         [][]string
	authenticated []bool
	problems      []string
}

func (c *recordingController) SetStatus(status string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.statuses = append(c.statuses, status)
}

func (c *recordingController) SetProblem(problem string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.problems = append(c.problems, problem)
}

// lastProblem is the marker currently in the menu bar, or "" if it was never
// set or was cleared.
func (c *recordingController) lastProblem() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.problems) == 0 {
		return ""
	}
	return c.problems[len(c.problems)-1]
}

func (c *recordingController) SetRepos(repos []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.repos = append(c.repos, append([]string(nil), repos...))
}

func (c *recordingController) SetAuthenticated(authenticated bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authenticated = append(c.authenticated, authenticated)
}

func (c *recordingController) SetUpdateAvailable(version, url string) {}

func (c *recordingController) Quit() {}

func (d *daemonState) watchedRepos() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	watched := make([]string, 0, len(d.syncers))
	for repoPath := range d.syncers {
		watched = append(watched, repoPath)
	}
	return watched
}

// Logging in twice preserves the existing syncer slice rather than spawning
// duplicate watcher goroutines.
func TestLoginTwiceDoesNotDuplicateWatchers(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)

	state := newDaemonState("https://api.test", "laptop", "", []string{"/repo/one", "/repo/two"}, nil)
	state.startAll(&recordingController{}, stop)
	state.login("pat_first")
	state.login("pat_second")

	if got := len(state.watchedRepos()); got != 2 {
		t.Fatalf("expected one watcher per repo, got %d", got)
	}
}

// The tray wires its menu handlers before it calls startAll; verify a login
// before startAll still properly starts watchers once initialized.
func TestLoginBeforeStartStillStartsWatchers(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)

	state := newDaemonState("https://api.test", "laptop", "", []string{"/repo/one"}, nil)
	state.login("pat_early")
	if got := len(state.watchedRepos()); got != 0 {
		t.Fatalf("nothing may start before the tray is ready, got %d watchers", got)
	}

	state.startAll(&recordingController{}, stop)
	if got := len(state.watchedRepos()); got != 1 {
		t.Fatalf("expected the pre-start login's token to be used, got %d watchers", got)
	}
}

func TestUnauthenticatedStartWatchesNothing(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)

	state := newDaemonState("https://api.test", "laptop", "", []string{"/repo/one"}, nil)
	state.startAll(&recordingController{}, stop)

	if got := len(state.watchedRepos()); got != 0 {
		t.Fatalf("expected no watchers without a token, got %d", got)
	}
}

func TestSetReposStartsWatchersAndReportsFreshState(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)

	ctl := &recordingController{}
	state := newDaemonState("https://api.test", "laptop", "pat_live", []string{"/repo/one"}, nil)
	state.startAll(ctl, stop)

	gotCtl, repos, status, _, authenticated := state.setRepos([]string{"/repo/one", "/repo/two"})
	if gotCtl != ctl {
		t.Fatal("expected the live controller back so the caller can update the menu")
	}
	if len(repos) != 2 || repos[1] != "/repo/two" {
		t.Fatalf("expected the added repo in the returned list, got %v", repos)
	}
	if !authenticated {
		t.Fatal("expected an authenticated daemon to report as such")
	}
	if status != "Treehouse • Active (Watching 2 repos)" {
		t.Fatalf("unexpected status %q", status)
	}
	if got := len(state.watchedRepos()); got != 2 {
		t.Fatalf("expected the added repo to be watched, got %d watchers", got)
	}
}

// The returned repo slice must be a copy: the caller hands it straight to the
// tray, which reads it on its own goroutine while setRepos may replace it.
func TestSetReposReturnsACopyOfTheRepoList(t *testing.T) {
	state := newDaemonState("https://api.test", "laptop", "pat_live", []string{"/repo/one"}, nil)
	_, repos, _, _, _ := state.setRepos([]string{"/repo/one", "/repo/two"})
	state.setRepos([]string{"/repo/one", "/repo/two", "/repo/three"})
	if len(repos) != 2 {
		t.Fatalf("the returned slice must not alias the state's own, got %v", repos)
	}
}

// A repo registered from a terminal while the tray is running reaches the
// daemon through the same reloaded list, so it gets a watcher too rather than
// waiting for a restart.
func TestSetReposPicksUpReposAddedOutsideTheTray(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)

	state := newDaemonState("https://api.test", "laptop", "pat_live", []string{"/repo/one"}, nil)
	state.startAll(&recordingController{}, stop)
	state.setRepos([]string{"/repo/one", "/repo/cli-added", "/repo/two"})

	if got := len(state.watchedRepos()); got != 3 {
		t.Fatalf("expected every repo in the reloaded config to be watched, got %d", got)
	}
}

// A repo dropped from config.json (e.g. by hand-editing it) must stop being
// watched once the tray or CLI reloads the list, not keep syncing until the
// daemon process restarts.
func TestSetReposStopsWatchersForRemovedRepos(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)

	state := newDaemonState("https://api.test", "laptop", "pat_live", []string{"/repo/one", "/repo/two"}, nil)
	state.startAll(&recordingController{}, stop)
	if got := len(state.watchedRepos()); got != 2 {
		t.Fatalf("expected both repos watched initially, got %d", got)
	}

	state.setRepos([]string{"/repo/one"})

	watched := state.watchedRepos()
	if len(watched) != 1 || watched[0] != "/repo/one" {
		t.Fatalf("expected only /repo/one still watched, got %v", watched)
	}
}

// The whole point of daemonState: every one of these is reachable from a
// different tray goroutine, and none of them may race. Fails under -race if
// any field loses its guard.
func TestDaemonStateIsSafeForConcurrentTrayCallbacks(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)

	ctl := &recordingController{}
	// Started authenticated on purpose: triggerAll's unauthenticated branch
	// shows a native alert, which a test must never pop.
	state := newDaemonState("https://api.test", "laptop", "pat_live", []string{"/repo/one"}, nil)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(4)
		go func() { defer wg.Done(); state.startAll(ctl, stop) }()
		go func() { defer wg.Done(); state.login("pat_live") }()
		go func() { defer wg.Done(); state.setRepos([]string{"/repo/one", "/repo/extra"}) }()
		go func() { defer wg.Done(); state.triggerAll() }()
	}
	wg.Wait()
}

// TestProblemClassification ensures sync failures are mapped to the appropriate
// problemKind for menu bar status indication.
func TestProblemClassification(t *testing.T) {
	for _, tc := range []struct {
		name        string
		err         error
		consecutive int
		want        problemKind
	}{
		{
			name: "revoked credential needs a login and nothing else helps",
			err:  &ingest.PushError{StatusCode: http.StatusUnauthorized},
			want: problemAuth,
		},
		{
			name: "plan capacity is the person's to resolve",
			err:  &ingest.PushError{StatusCode: http.StatusForbidden, Code: "ENTITLEMENT_LIMIT_EXCEEDED"},
			want: problemCapacity,
		},
		{
			name: "another 403 is permanent but not a login",
			err:  &ingest.PushError{StatusCode: http.StatusForbidden},
			want: problemBlocked,
		},
		{
			// The server asked for a pause and the syncer is already obeying
			// it. Reporting this would alarm someone about the system working.
			name:        "being rate limited is not a problem to report",
			err:         &ingest.PushError{StatusCode: http.StatusTooManyRequests, RetryAfter: time.Minute},
			consecutive: 9,
			want:        problemNone,
		},
		{
			name:        "one missed push while a laptop wakes up stays quiet",
			err:         errors.New("dial tcp: connection refused"),
			consecutive: 1,
			want:        problemNone,
		},
		{
			name:        "but a server unreachable for three tries running is worth saying",
			err:         errors.New("dial tcp: connection refused"),
			consecutive: offlineFailureThreshold,
			want:        problemOffline,
		},
		{
			name:        "a persistent 5xx reads as offline, never as permanent",
			err:         &ingest.PushError{StatusCode: http.StatusBadGateway},
			consecutive: offlineFailureThreshold,
			want:        problemOffline,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyPushFailure(tc.err, tc.consecutive); got != tc.want {
				t.Fatalf("classifyPushFailure = %v, want %v", got, tc.want)
			}
		})
	}
}

// Every reportable problem has to produce text for both surfaces, or a repo
// stops syncing and still shows nothing.
func TestEveryProblemHasText(t *testing.T) {
	for _, kind := range []problemKind{problemOffline, problemBlocked, problemCapacity, problemAuth} {
		if kind.menuBarText() == "" {
			t.Fatalf("problem %v has no menu bar marker", kind)
		}
		if kind.statusText() == "" {
			t.Fatalf("problem %v has no status line", kind)
		}
		// The marker sits in a bar the user has already filled with other
		// apps; macOS gives it exactly the width it asks for.
		if len([]rune(kind.menuBarText())) > 16 {
			t.Fatalf("menu bar marker %q is too long for the menu bar", kind.menuBarText())
		}
	}
	if problemNone.menuBarText() != "" || problemNone.statusText() != "" {
		t.Fatal("a healthy daemon must show nothing at all")
	}
}

func newProblemTestState(t *testing.T, repos ...string) (*daemonState, *recordingController) {
	t.Helper()
	state := newDaemonState("https://api.example.com", "laptop", "token", repos, nil)
	ctl := &recordingController{}
	state.mu.Lock()
	state.ctl = ctl
	state.mu.Unlock()
	return state, ctl
}

func TestProblemReachesTheMenuBarAndClearsOnRecovery(t *testing.T) {
	state, ctl := newProblemTestState(t, "/a")

	state.recordSyncOutcome("/a", problemAuth)
	if got := ctl.lastProblem(); got != "⚠ Sign in" {
		t.Fatalf("menu bar marker = %q, want the sign-in marker", got)
	}
	state.mu.Lock()
	status := state.statusLocked()
	state.mu.Unlock()
	if !strings.Contains(status, "Sign in again") {
		t.Fatalf("status = %q, want it to name the problem", status)
	}

	state.recordSyncOutcome("/a", problemNone)
	if got := ctl.lastProblem(); got != "" {
		t.Fatalf("a recovered daemon must clear the marker, got %q", got)
	}
	state.mu.Lock()
	status = state.statusLocked()
	state.mu.Unlock()
	if !strings.Contains(status, "Active") {
		t.Fatalf("status = %q, want it back to active", status)
	}
}

// Severity, not recency: a machine whose token was revoked and whose network
// is also flaky should say "sign in", because that is the only thing that
// helps and the only thing a person can do.
func TestWorstProblemWins(t *testing.T) {
	state, ctl := newProblemTestState(t, "/a", "/b")

	state.recordSyncOutcome("/a", problemOffline)
	state.recordSyncOutcome("/b", problemAuth)
	if got := ctl.lastProblem(); got != "⚠ Sign in" {
		t.Fatalf("marker = %q, want the more severe problem to win", got)
	}

	// The severe one clearing must fall back to the one still outstanding,
	// not to silence.
	state.recordSyncOutcome("/b", problemNone)
	if got := ctl.lastProblem(); got != "⚠ Offline" {
		t.Fatalf("marker = %q, want the remaining problem to show", got)
	}
}

// A repo nobody watches any more must not keep complaining: its last failure
// is no longer a condition anyone can act on.
func TestUnwatchingARepoClearsItsProblem(t *testing.T) {
	state, _ := newProblemTestState(t, "/a", "/b")
	state.recordSyncOutcome("/a", problemCapacity)

	state.setRepos([]string{"/b"})

	state.mu.Lock()
	remaining := state.worstProblemLocked()
	state.mu.Unlock()
	if remaining != problemNone {
		t.Fatalf("a removed repo left %v behind", remaining)
	}
}

// The tray is only told when the aggregate actually moves. Otherwise every
// heartbeat of a persistently broken repo would be an AppKit call.
func TestUnchangedProblemDoesNotRepaintTheMenuBar(t *testing.T) {
	state, ctl := newProblemTestState(t, "/a")

	for i := 0; i < 5; i++ {
		state.recordSyncOutcome("/a", problemOffline)
	}

	ctl.mu.Lock()
	defer ctl.mu.Unlock()
	if len(ctl.problems) != 1 {
		t.Fatalf("expected one menu bar update, got %d", len(ctl.problems))
	}
}

// A successful login resolves every complaint the old credential caused.
// Without this the menu bar still said "Sign in" after signing in, until each
// repo happened to sync and report otherwise.
func TestLoginClearsStaleProblems(t *testing.T) {
	state, _ := newProblemTestState(t, "/a")
	state.recordSyncOutcome("/a", problemAuth)

	_, status, problem := state.login("pat_new")

	if problem != "" {
		t.Fatalf("login left %q in the menu bar", problem)
	}
	if !strings.Contains(status, "Active") {
		t.Fatalf("status = %q, want it back to active after logging in", status)
	}
}

// TestCapacityRejectionReachesTheMenuBarAsAPlanLimit verifies that a 403 Forbidden
// response with ENTITLEMENT_LIMIT_EXCEEDED correctly triggers a problemPlanLimit.
func TestCapacityRejectionReachesTheMenuBarAsAPlanLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"treehouse machine limit reached","code":"ENTITLEMENT_LIMIT_EXCEEDED"}`))
	}))
	defer server.Close()

	_, err := ingest.Push(server.URL, "token", ingest.RepoSnapshotPayload{
		MachineName: "laptop", RepoPath: "/repo", RepoName: "repo",
	})
	if err == nil {
		t.Fatal("expected the capacity rejection to surface as an error")
	}

	if got := classifyPushFailure(err, 1); got != problemCapacity {
		t.Fatalf("classifyPushFailure = %v, want problemCapacity", got)
	}
	if got := problemCapacity.menuBarText(); got != "⚠ Plan limit" {
		t.Fatalf("menu bar marker = %q", got)
	}
}

// A capacity block is not terminal: it clears the moment someone upgrades or
// removes a machine, and the daemon has to notice without being restarted.
// So it keeps retrying, just slowly -- the ceiling is what makes that cheap.
func TestCapacityBlockKeepsRetryingSlowly(t *testing.T) {
	s := newRepoSyncer("", "", "laptop", "/repo", nil, nil)
	for i := 0; i < 20; i++ {
		s.noteResult(&ingest.PushError{
			StatusCode: http.StatusForbidden,
			Code:       "ENTITLEMENT_LIMIT_EXCEEDED",
		})
	}

	s.mu.Lock()
	wait := time.Until(s.notBefore)
	s.mu.Unlock()

	if wait > syncBackoffMax {
		t.Fatalf("backoff ran past its ceiling: %v", wait)
	}
	if wait < syncBackoffMax/2 {
		t.Fatalf("a repeatedly refused repo must back off to the ceiling, waiting only %v", wait)
	}
}
