package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/cloptima/cloptima-treehouse/internal/auth"
	"github.com/cloptima/cloptima-treehouse/internal/config"
	"github.com/cloptima/cloptima-treehouse/internal/crypto"
	"github.com/cloptima/cloptima-treehouse/internal/git"
	"github.com/cloptima/cloptima-treehouse/internal/ingest"
	"github.com/cloptima/cloptima-treehouse/internal/loginitem"
	"github.com/cloptima/cloptima-treehouse/internal/payload"
	"github.com/cloptima/cloptima-treehouse/internal/tray"
	"github.com/cloptima/cloptima-treehouse/internal/update"
	"github.com/cloptima/cloptima-treehouse/internal/watch"
	"github.com/spf13/cobra"
)

// worktreeDiscoveryInterval bounds how long it takes to notice a worktree
// created or removed after `treehouse run` starts. fsnotify has no way to
// learn about a sibling directory it was never told to watch, so this is a
// plain poll rather than an event -- kept coarse since `git worktree add`
// is a rare, deliberate action, not something worth reacting to instantly.
const worktreeDiscoveryInterval = 30 * time.Second

// heartbeatInterval keeps a repo syncing while nothing about it is changing.
// fsnotify only fires on change, so without this an idle-but-running daemon is
// indistinguishable from one that was killed: the machine list shows a
// days-old "last seen" for a laptop that is sitting there working fine, and
// the server-side diff cache eventually expires, which costs the settle check
// its ability to notice the first edit after a long quiet spell.
//
// A heartbeat cannot disturb the settle clock. An unchanged snapshot matches
// both halves of the server's comparison -- the stored worktree structure and
// the cached diff signature -- so last_changed_at is preserved and no
// notification is scheduled. Five minutes keeps "last seen" reading as live
// without the traffic mattering: one `git status` per worktree and one POST
// per repo.
const heartbeatInterval = 5 * time.Minute

func newRunCommand() *cobra.Command {
	var noTray bool
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Watch every registered repo and push status/diff snapshots",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDaemon(cmd, noTray)
		},
	}
	cmd.Flags().BoolVar(&noTray, "no-tray", false, "Run in headless console mode without macOS menu bar tray")
	cmd.Flags().BoolVar(&noTray, "headless", false, "Alias for --no-tray")
	return cmd
}

// resolveMachineName is the name this machine registers itself under, and is
// also the identity the browser login flow ties the minted token to (see
// auth.Login), so both entry points must derive it identically.
func resolveMachineName(cfg *config.Config) string {
	if cfg.MachineName != "" {
		return cfg.MachineName
	}
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		return hostname
	}
	return "unknown-machine"
}

// A sync failure is classified so actionable problems (auth failure, plan
// limits) are surfaced directly to the user in the menu bar and logs, while
// transient network blips are filtered until they persist.
type problemKind int

const (
	problemNone problemKind = iota
	// problemOffline is a transport failure or a 5xx: real, but self-healing,
	// so it is only surfaced once a repo has failed enough times in a row that
	// it is clearly not a blip.
	problemOffline
	// problemBlocked is a 4xx the person cannot act on directly -- a malformed
	// snapshot, a machine bound to someone else. Rare, permanent, and worth
	// naming rather than retrying forever.
	problemBlocked
	// problemCapacity is the plan's machine or worktree limit. Permanent until
	// they upgrade or free something up.
	problemCapacity
	// problemAuth is a missing, expired or revoked credential. The most severe
	// because nothing syncs at all and only a login fixes it.
	problemAuth
)

// menuBarText is the marker shown beside the icon in the menu bar. Very short
// on purpose: it competes with every other menu bar app for room, and macOS
// gives it exactly the width it asks for.
func (k problemKind) menuBarText() string {
	switch k {
	case problemAuth:
		return "⚠ Sign in"
	case problemCapacity:
		return "⚠ Plan limit"
	case problemBlocked:
		return "⚠ Blocked"
	case problemOffline:
		return "⚠ Offline"
	default:
		return ""
	}
}

// statusText is the fuller line for the dropdown, where there is room for a
// clause but still not for a sentence.
func (k problemKind) statusText() string {
	switch k {
	case problemAuth:
		return "Treehouse • Sign in again — not syncing"
	case problemCapacity:
		return "Treehouse • Plan limit reached — not syncing"
	case problemBlocked:
		return "Treehouse • Sync rejected — see the log"
	case problemOffline:
		return "Treehouse • Can't reach Cloptima — retrying"
	default:
		return ""
	}
}

// classifyPushFailure maps one failed sync onto what the person should be
// told, and whether retrying can help.
//
// consecutive is how many times this repo has failed in a row, and it only
// matters for the transient case: a single missed push while a laptop wakes up
// is not worth a menu bar marker, but a repo that has failed every attempt for
// half an hour is.
func classifyPushFailure(err error, consecutive int) problemKind {
	var pushErr *ingest.PushError
	if !errors.As(err, &pushErr) {
		// Not an answer from the server at all: DNS, a refused connection, a
		// timeout. Transient by nature.
		if consecutive >= offlineFailureThreshold {
			return problemOffline
		}
		return problemNone
	}
	switch {
	case pushErr.StatusCode == http.StatusUnauthorized:
		return problemAuth
	case pushErr.Code == entitlementLimitCode:
		return problemCapacity
	case pushErr.Permanent():
		// A 403 that is not a capacity limit: access is disabled, the token
		// carries no machine binding, or the machine belongs to another account.
		// All need a person; none is a login.
		return problemBlocked
	case pushErr.RateLimited():
		// Not a problem to report. The server asked for a pause and the syncer
		// is already honouring it; saying "offline" here would alarm someone
		// about the system working as designed.
		return problemNone
	case pushErr.StatusCode >= 400 && pushErr.StatusCode < 500:
		return problemBlocked
	default:
		if consecutive >= offlineFailureThreshold {
			return problemOffline
		}
		return problemNone
	}
}

// entitlementLimitCode is the machine-readable code the server sends when
// account machine or worktree capacity is reached.
const entitlementLimitCode = "ENTITLEMENT_LIMIT_EXCEEDED"

// offlineFailureThreshold is how many consecutive failures a repo needs before
// a transient fault is called a problem. Three, against a five-minute
// heartbeat, so a closed lid or a train tunnel stays quiet and a genuinely
// unreachable server does not.
const offlineFailureThreshold = 3

// daemonState owns every piece of state the tray shares with the daemon.
// The tray runs each menu handler on its own goroutine while startAll and the
// per-repo watchers run on others, so nothing here may be read or written
// without holding mu -- the previous shape captured these as plain closure
// variables, which raced.
type daemonState struct {
	apiGatewayURL string
	machineName   string
	// identity is this machine's instance id and its content/token keys,
	// shared by every syncer: one machine has one content key, whatever it is
	// watching.
	identity *crypto.Identity

	mu      sync.Mutex
	token   string
	repos   []string
	syncers map[string]*watchedRepo
	ctl     tray.Controller
	stopCh  <-chan struct{}
	started bool

	// problems is the last classified outcome per repo. Keyed by path so a
	// repo that recovers clears its own entry rather than the whole set, and
	// so an unwatched repo's stale complaint goes when its watcher does.
	problems map[string]problemKind

	// checkForUpdates gates the periodic release check startAll otherwise
	// starts. Only runDaemon turns it on; tests construct daemonState
	// directly and never do, so they never make a network call to GitHub.
	checkForUpdates bool
}

// watchedRepo pairs a running repoSyncer with a way to stop just its own
// watcher goroutines. Without a per-repo stop, the only way to tear down a
// watcher was closing the daemon's single shared stopCh, which meant a repo
// dropped from the config could never actually be unwatched before the whole
// process exited.
type watchedRepo struct {
	syncer *repoSyncer
	stop   func()
}

func newDaemonState(apiGatewayURL, machineName, token string, repos []string, identity *crypto.Identity) *daemonState {
	return &daemonState{
		apiGatewayURL: apiGatewayURL,
		machineName:   machineName,
		identity:      identity,
		token:         token,
		repos:         append([]string(nil), repos...),
		syncers:       make(map[string]*watchedRepo),
		problems:      make(map[string]problemKind),
	}
}

// stopOrParent returns a channel that closes as soon as either parent closes
// or the returned function is called, so a watcher can be stopped on its own
// without racing the daemon's shared shutdown signal.
func stopOrParent(parent <-chan struct{}) (stop <-chan struct{}, stopFn func()) {
	ch := make(chan struct{})
	var once sync.Once
	closeCh := func() { once.Do(func() { close(ch) }) }
	go func() {
		select {
		case <-parent:
		case <-ch:
		}
		closeCh()
	}()
	return ch, closeCh
}

// ensureWatchers reconciles the running watchers against d.repos: it starts a
// watcher for every registered repo that does not already have one, and stops
// the watcher for any repo that is no longer registered. Keying by repo path
// rather than appending makes starting idempotent, which is what lets
// startAll, login, and addRepo all just call it: logging in a second time no
// longer spawns a duplicate set of watchers alongside the first.
//
// Callers must hold mu. Nothing runs before a token exists, so each syncer
// capturing the token at creation is safe -- the tray hides Log In once
// authenticated, so the token never changes underneath a live watcher.
func (d *daemonState) ensureWatchers() {
	if !d.started || d.token == "" || d.stopCh == nil {
		return
	}
	current := make(map[string]bool, len(d.repos))
	for _, repoPath := range d.repos {
		current[repoPath] = true
		if _, ok := d.syncers[repoPath]; ok {
			continue
		}
		stop, stopFn := stopOrParent(d.stopCh)
		syncer := newRepoSyncer(d.apiGatewayURL, d.token, d.machineName, repoPath, d.identity, stop)
		syncer.onOutcome = d.recordSyncOutcome
		d.syncers[repoPath] = &watchedRepo{syncer: syncer, stop: stopFn}
		go watchRepoWithSyncer(stop, syncer, repoPath)
	}
	for repoPath, watched := range d.syncers {
		if current[repoPath] {
			continue
		}
		watched.stop()
		delete(d.syncers, repoPath)
	}
}

// startAll is the tray's "menu is ready" callback. A Log In click can land
// before it does -- the menu's handler goroutines are wired first -- so this
// starts whatever the state holds by then rather than assuming it is still
// the token runDaemon read at startup.
func (d *daemonState) startAll(ctl tray.Controller, stop <-chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ctl = ctl
	d.stopCh = stop
	d.started = true
	if ctl != nil && d.checkForUpdates {
		go d.watchForUpdates(ctl, stop)
	}
	if d.token == "" {
		log.Println("treehouse: not logged in; run `treehouse login` to authenticate")
		return
	}
	d.ensureWatchers()
}

// updateCheckInterval balances staleness against load: GitHub's anonymous
// API rate limit is 60 requests/hour per IP, and this is one request per
// running daemon per interval.
const updateCheckInterval = 6 * time.Hour

// watchForUpdates checks once immediately (so a long-running launch doesn't
// wait 6 hours to learn it's stale) and then on updateCheckInterval until
// stop closes. Whether the user is logged in doesn't matter -- an update
// exists independent of auth state.
func (d *daemonState) watchForUpdates(ctl tray.Controller, stop <-chan struct{}) {
	check := func() {
		info, err := update.Check(version)
		if err != nil {
			log.Printf("treehouse: update check failed: %v", err)
			return
		}
		if info.Available {
			ctl.SetUpdateAvailable(info.Version, info.URL)
		}
	}
	check()

	ticker := time.NewTicker(updateCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			check()
		}
	}
}

func (d *daemonState) triggerAll() {
	d.mu.Lock()
	if d.token == "" {
		d.mu.Unlock()
		_ = tray.ShowAlert("Authentication Required", "Log in from the menu bar (or run `treehouse login`) before syncing.")
		return
	}
	pending := make([]*repoSyncer, 0, len(d.syncers))
	for _, watched := range d.syncers {
		pending = append(pending, watched.syncer)
	}
	d.mu.Unlock()

	for _, syncer := range pending {
		syncer.Trigger()
	}
}

// recordSyncOutcome takes one repo's result and pushes the aggregate to the
// tray, so a daemon that has stopped working says so where it can be seen.
//
// Called from each syncer's own goroutine, which is why the controller calls
// happen after the lock is released: SetProblem reaches AppKit, and holding
// the state mutex across it would let a slow menu bar redraw block every
// running sync.
func (d *daemonState) recordSyncOutcome(repoPath string, kind problemKind) {
	d.mu.Lock()
	previous := d.problems[repoPath]
	if kind == problemNone {
		delete(d.problems, repoPath)
	} else {
		d.problems[repoPath] = kind
	}
	if previous == kind {
		d.mu.Unlock()
		return
	}
	ctl, status, marker := d.publishableLocked()
	d.mu.Unlock()

	// Logged on the transition, not on every failing sync, and logged whether
	// or not a tray exists: `--headless` has no menu bar, and a server
	// operator reading journald needs the same one line the menu bar shows.
	if kind == problemNone {
		log.Printf("treehouse: %s is syncing again", repoPath)
	} else {
		log.Printf("treehouse: %s -- %s", repoPath, kind.statusText())
	}

	if ctl == nil {
		return
	}
	ctl.SetStatus(status)
	ctl.SetProblem(marker)
}

// publishableLocked returns everything the tray needs to render current state.
// Caller must hold mu, and must release it before calling into the controller:
// SetProblem reaches AppKit, and holding the state mutex across a menu bar
// redraw would block every running sync behind it.
func (d *daemonState) publishableLocked() (tray.Controller, string, string) {
	return d.ctl, d.statusLocked(), d.worstProblemLocked().menuBarText()
}

// pruneProblemsLocked drops complaints about repos that are no longer
// registered. A repo nobody watches any more must not keep a marker in the
// menu bar: its last failure is not a condition anyone can act on, and the
// only way to clear it would be to re-add the repo.
//
// Done here rather than in ensureWatchers' removal loop, which is behind an
// early return that skips it whenever no watchers are running -- exactly the
// signed-out case where a stale complaint is most likely to be left over.
func (d *daemonState) pruneProblemsLocked() {
	registered := make(map[string]bool, len(d.repos))
	for _, repoPath := range d.repos {
		registered[repoPath] = true
	}
	for repoPath := range d.problems {
		if !registered[repoPath] {
			delete(d.problems, repoPath)
		}
	}
}

// worstProblemLocked is the one condition worth a single marker.
//
// Severity order, not most recent and not most common: a machine whose token
// has been revoked and whose network is also flaky should say "sign in", not
// "offline", because fixing the login is the only thing that helps and it is
// the thing a person can do.
func (d *daemonState) worstProblemLocked() problemKind {
	worst := problemNone
	for _, kind := range d.problems {
		if kind > worst {
			worst = kind
		}
	}
	return worst
}

// status renders the menu bar header. Caller must hold mu.
func (d *daemonState) statusLocked() string {
	if d.token == "" {
		return "Treehouse • Not Logged In"
	}
	if problem := d.worstProblemLocked(); problem != problemNone {
		return problem.statusText()
	}
	return fmt.Sprintf("Treehouse • Active (Watching %d repos)", len(d.repos))
}

// setRepos replaces the watched set with what the config file now holds,
// rather than appending just the one repo the tray added. `treehouse add`
// from a terminal writes the same file, so taking the reloaded list means a
// repo registered that way is picked up too instead of the menu and the
// config drifting apart. ensureWatchers reconciles both directions: a repo
// newly present gets a watcher, and one no longer present has its watcher
// stopped instead of continuing to sync a repo the user removed.
func (d *daemonState) setRepos(repos []string) (ctl tray.Controller, current []string, status, problem string, authenticated bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.repos = append([]string(nil), repos...)
	d.pruneProblemsLocked()
	d.ensureWatchers()
	ctl, status, problem = d.publishableLocked()
	return ctl, append([]string(nil), d.repos...), status, problem, d.token != ""
}

func (d *daemonState) login(token string) (ctl tray.Controller, status, problem string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.token = token
	// A fresh credential resolves every complaint the old one caused, and the
	// watchers about to start will report the truth within a heartbeat.
	// Leaving the old markers up would have a successful login still say
	// "Sign in" until each repo happened to sync.
	d.problems = make(map[string]problemKind)
	d.ensureWatchers()
	ctl, status, problem = d.publishableLocked()
	return ctl, status, problem
}

func runDaemon(cmd *cobra.Command, noTray bool) error {
	token, err := auth.AccessToken()
	if err != nil && !errors.Is(err, auth.ErrNoAccessToken) {
		// A keychain that is locked, or denied to this binary, is not the same
		// as never having logged in: reporting it as "not logged in" sends the
		// user round the login flow again to fix something login cannot fix.
		return err
	}
	cfg, cfgErr := config.Load()
	if cfgErr != nil {
		return cfgErr
	}

	// The menu bar needs an application bundle, which the Homebrew formula's
	// bare binary is not (see tray.Available). Deciding here rather than
	// inside tray.Run keeps one headless path instead of two, and means the
	// formula install reports what it is doing instead of entering an event
	// loop that can never draw an icon.
	headless := noTray || !tray.Available()
	if len(cfg.Repos) == 0 && headless {
		return fmt.Errorf("no repos registered; run `treehouse add <path>` first")
	}

	// One daemon per machine. The cask's menu bar app and the formula's
	// headless binary are the same daemon over the same config, so nothing
	// stops someone installing both and watching every repo twice.
	//
	// Taken before any watcher starts, and released when this function
	// returns -- including the tray path, where tray.Run blocks until Quit.
	releaseLock, err := config.AcquireDaemonLock()
	if err != nil {
		var running *config.ErrDaemonRunning
		if errors.As(err, &running) && !headless {
			// A double-clicked app has no terminal to print to, so the only
			// way it can say anything at all is a native alert.
			_ = tray.ShowAlert("Already Running", running.Error()+". Quit the running copy first.")
		}
		return err
	}
	defer func() { _ = releaseLock() }()

	apiGatewayURL := cfg.APIGatewayURL
	if apiGatewayURL == "" {
		apiGatewayURL = defaultAPIGatewayURL
	}
	machineName := resolveMachineName(cfg)
	// Resolved once, at startup, and threaded to every syncer. Generated on
	// first run and reused thereafter: a machine keeps one identity across a
	// rename, and two hosts that happen to share a hostname stay distinct.
	// Phase 1 does not yet seal diffs with the keys, but grants wrap the
	// content key, so it has to exist and be stable before any device can be
	// granted anything.
	identity, err := crypto.EnsureIn(crypto.KeyringStore(), os.Getenv(crypto.EnvMachineIdentity))
	if err != nil {
		return err
	}
	state := newDaemonState(apiGatewayURL, machineName, token, cfg.Repos, identity)
	state.checkForUpdates = true

	onAddRepo := func() {
		selectedPath, err := tray.PromptChooseFolder()
		if err != nil {
			_ = tray.ShowAlert("Could Not Open Folder Picker", fmt.Sprintf("%v", err))
			return
		}
		if selectedPath == "" {
			return // user canceled
		}
		abs, err := filepath.Abs(selectedPath)
		if err != nil {
			return
		}
		if !isGitRepo(abs) {
			_ = tray.ShowAlert("Not a Git Repository", fmt.Sprintf("%q has no .git.", filepath.Base(abs)))
			return
		}

		freshCfg, err := config.Load()
		if err != nil {
			_ = tray.ShowAlert("Could Not Load Config", fmt.Sprintf("%v", err))
			return
		}
		if !freshCfg.AddRepo(abs) {
			_ = tray.ShowNotification("Treehouse", fmt.Sprintf("%s is already registered", filepath.Base(abs)))
			return
		}
		if err := config.Save(freshCfg); err != nil {
			_ = tray.ShowAlert("Could Not Save Config", fmt.Sprintf("%v", err))
			return
		}

		ctl, repos, status, problem, authenticated := state.setRepos(freshCfg.Repos)
		if ctl != nil {
			ctl.SetRepos(repos)
			ctl.SetStatus(status)
			ctl.SetProblem(problem)
		}
		if authenticated {
			_ = tray.ShowNotification("Treehouse", fmt.Sprintf("Watching %s", filepath.Base(abs)))
		} else {
			_ = tray.ShowNotification("Treehouse", fmt.Sprintf("Added %s. Log in to begin syncing.", filepath.Base(abs)))
		}
	}

	onLogin := func() {
		// nil writer: the tray login path has no terminal to print a
		// copy-paste fallback URL to, and always has a working browser.
		newToken, err := auth.Login(tray.ResolveWebURL(apiGatewayURL), machineName, identity.InstanceID.String(), nil)
		if err != nil {
			_ = tray.ShowAlert("Login Failed", fmt.Sprintf("%v", err))
			return
		}
		ctl, status, problem := state.login(newToken)
		if ctl != nil {
			ctl.SetAuthenticated(true)
			ctl.SetStatus(status)
			ctl.SetProblem(problem)
		}
		_ = tray.ShowNotification("Treehouse", "Successfully authenticated with Cloptima")
	}

	if headless {
		// Only worth saying when a tray was actually expected: --no-tray asked
		// for this, so explaining it would be noise.
		if !noTray {
			fmt.Fprintln(cmd.OutOrStdout(), tray.UnavailableNotice())
		}
		if token == "" {
			return fmt.Errorf("not logged in; run `treehouse login` first")
		}
		stop := make(chan struct{})
		state.startAll(nil, stop)
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		fmt.Fprintf(cmd.OutOrStdout(), "watching %d repo(s), press Ctrl+C to stop\n", len(cfg.Repos))
		<-sig
		close(stop)
		return nil
	}

	// A signed-out launch otherwise sits silent until someone happens to open
	// the menu bar icon. Runs concurrently with tray startup below, not
	// before it -- the alert doesn't depend on the tray icon existing.
	if token == "" {
		go func() {
			if loginNow, _ := tray.ShowLoginPrompt("Log In?", "Nothing will sync until you sign in."); loginNow {
				onLogin()
			}
		}()
	}

	// Launch at Login is a menu bar affordance only: the headless formula
	// install has no application bundle for SMAppService to register. A fresh
	// install has no saved preference, so reconcileLaunchAtLogin defaults it
	// on, registers the app, and persists the choice.
	launchAtLoginChecked := false
	var onToggleLaunchAtLogin func(enable bool) bool
	if loginitem.Supported() {
		launchAtLoginChecked = reconcileLaunchAtLogin(cfg)
		onToggleLaunchAtLogin = applyLaunchAtLogin
	}

	opts := tray.Options{
		Version:               version,
		APIGatewayURL:         apiGatewayURL,
		Repos:                 cfg.Repos,
		Authenticated:         token != "",
		OnSyncNow:             state.triggerAll,
		OnAddRepo:             onAddRepo,
		OnLogin:               onLogin,
		LaunchAtLoginChecked:  launchAtLoginChecked,
		OnToggleLaunchAtLogin: onToggleLaunchAtLogin,
	}
	return tray.Run(opts, state.startAll)
}

// watchRepoWithSyncer keeps one repo's set of worktree watchers reconciled
// against `git worktree list` for as long as stop is open: a worktree created
// after the daemon started (`git worktree add`) gets its own watcher within
// worktreeDiscoveryInterval instead of only after a restart, and one removed
// (`git worktree remove`) has its watcher torn down instead of left pointing
// at a directory that no longer exists.
func watchRepoWithSyncer(stop <-chan struct{}, syncer *repoSyncer, repoPath string) {
	watchers := make(map[string]*watch.Watcher)
	triggerSync := syncer.Trigger

	reconcile := func() {
		worktreePaths, err := git.ListWorktrees(repoPath)
		if err != nil {
			log.Printf("treehouse: failed to list worktrees for %s: %v", repoPath, err)
			return
		}
		current := make(map[string]bool, len(worktreePaths))
		for _, wtPath := range worktreePaths {
			current[wtPath] = true
			if _, ok := watchers[wtPath]; ok {
				continue
			}
			w, err := watch.New(wtPath, triggerSync)
			if err != nil {
				log.Printf("treehouse: failed to watch %s: %v", wtPath, err)
				continue
			}
			watchers[wtPath] = w
			go w.Run(stop)
		}
		for wtPath, w := range watchers {
			if current[wtPath] {
				continue
			}
			_ = w.Close()
			delete(watchers, wtPath)
		}
	}

	// reconcile() runs only from this goroutine (the initial call below and
	// the ticker loop), so the watchers map never needs its own lock.
	reconcile()
	triggerSync() // initial sync so state is fresh immediately, not only after the first fs event

	runWatchLoop(stop, worktreeDiscoveryInterval, heartbeatInterval, heartbeatJitter(), reconcile, triggerSync)
}

// heartbeatJitter is a random offset applied once, to this repo's first
// heartbeat only.
//
// Every repo's watcher starts within milliseconds of the others -- daemon
// launch, or a login that starts them all at once -- so without an offset all
// of them tick together, delivering their heartbeat load in a synchronized burst.
// Spreading the phase smooths traffic and avoids unnecessary collisions.
//
// Applied to the phase, never to the interval: each repo still heartbeats
// exactly once per heartbeatInterval, just not at the same instant as its
// neighbours. The 3s change debounce is untouched -- this delays nothing a
// person did, only the periodic keepalive nobody is waiting on.
func heartbeatJitter() time.Duration {
	return time.Duration(rand.Int64N(int64(heartbeatInterval)))
}

// runWatchLoop drives the two periodic jobs a watched repo needs until stop is
// closed: rediscovering worktrees, and the heartbeat sync. Separated from
// watchRepoWithSyncer so the cadence can be exercised without waiting
// minutes for it.
func runWatchLoop(
	stop <-chan struct{},
	discoveryInterval, heartbeat, heartbeatOffset time.Duration,
	reconcile, triggerSync func(),
) {
	discoveryTicker := time.NewTicker(discoveryInterval)
	defer discoveryTicker.Stop()

	// The offset is spent once, on a timer, before the steady ticker starts.
	// Shifting the phase this way rather than varying the interval keeps every
	// repo on exactly one heartbeat per interval.
	var heartbeatC <-chan time.Time
	offsetTimer := time.NewTimer(heartbeatOffset)
	defer offsetTimer.Stop()
	var heartbeatTicker *time.Ticker
	defer func() {
		if heartbeatTicker != nil {
			heartbeatTicker.Stop()
		}
	}()

	for {
		select {
		case <-stop:
			return
		case <-discoveryTicker.C:
			reconcile()
		case <-offsetTimer.C:
			heartbeatTicker = time.NewTicker(heartbeat)
			heartbeatC = heartbeatTicker.C
			triggerSync()
		case <-heartbeatC:
			triggerSync()
		}
	}
}

// repoSyncer serializes every sync for one repo. Each of a repo's worktrees
// gets its own watcher with its own debounce timer, and they all report the
// same whole-repo snapshot, so without this several full syncs run at once --
// each reading git state at a different instant. Whichever request the server
// happens to handle last wins, so an older snapshot can overwrite a newer one
// and pin stale status and diffs until the next filesystem event.
//
// Overlapping triggers coalesce into exactly one follow-up run rather than
// queueing: every trigger asks the same question ("what does this repo look
// like now?"), so N pending triggers and one pending trigger have identical
// answers.
type repoSyncer struct {
	apiGatewayURL string
	token         string
	machineName   string
	repoPath      string

	mu      sync.Mutex
	running bool
	pending bool

	// lastPushed and lastStructure record what the server was last told, so a
	// heartbeat that changes nothing can be sent without its diff bodies (see
	// ingest.RepoSnapshotPayload.Lean). Both are touched only from inside a
	// sync, and run() serializes those -- the mutex above orders one sync's
	// writes before the next sync's reads even when they land on different
	// goroutines.
	lastPushed    map[string]string
	lastStructure string

	// identity names this machine on every push and wraps MCK for the reader
	// devices the server reports as pending. Nil in tests that only exercise
	// the concurrency behaviour and never reach a push.
	identity *crypto.Identity

	// pendingGrants holds wraps produced from the last response, to be sent
	// with the next push. Guarded by mu: the response arrives on one sync and
	// the next sync reads it.
	pendingGrants map[string]string

	// syncFn is the work one run performs. Production always uses sync;
	// tests replace it to observe the concurrency behaviour without a server.
	syncFn func() error

	// stop closes when this repo is unwatched or the daemon shuts down. Held
	// so a backoff wait can be interrupted rather than pinning a goroutine
	// past the daemon's own lifetime.
	stop <-chan struct{}

	// onOutcome reports each run's classified result to the daemon so the
	// menu bar can show it. Nil in tests that only exercise the concurrency
	// behaviour.
	onOutcome func(repoPath string, kind problemKind)

	// notBefore is when the next attempt may run, and consecutiveFailures is
	// what sizes it. Both guarded by mu.
	//
	// The gate exists because run() loops while a sync is pending, and
	// fsnotify keeps producing events whether or not pushes are landing -- so
	// a repo failing every attempt retried as fast as the debounce allowed,
	// forever, against a server that had already said no. A permanent
	// rejection made that worst: the daemon hammered an endpoint that could
	// never accept it until someone noticed the app was empty.
	notBefore           time.Time
	consecutiveFailures int
}

// Backoff bounds for a repo that keeps failing.
//
// The ceiling sits just above the five-minute heartbeat, so a repo in the
// worst case still retries about as often as an idle one syncs -- far enough
// apart to stop hammering, close enough that recovery is noticed without a
// restart. A server-sent Retry-After always wins over this.
const (
	syncBackoffBase = 30 * time.Second
	syncBackoffMax  = 6 * time.Minute
)

// backoffFor is exponential in the number of consecutive failures, capped.
func backoffFor(consecutiveFailures int) time.Duration {
	if consecutiveFailures <= 0 {
		return 0
	}
	backoff := syncBackoffBase
	for i := 1; i < consecutiveFailures && backoff < syncBackoffMax; i++ {
		backoff *= 2
	}
	if backoff > syncBackoffMax {
		backoff = syncBackoffMax
	}
	return backoff
}

// noteResult records one run's outcome, sets the next attempt's earliest start,
// and reports what the person should be told.
func (s *repoSyncer) noteResult(err error) {
	s.mu.Lock()
	if err == nil {
		s.consecutiveFailures = 0
		s.notBefore = time.Time{}
		s.mu.Unlock()
		if s.onOutcome != nil {
			s.onOutcome(s.repoPath, problemNone)
		}
		return
	}

	s.consecutiveFailures++
	consecutive := s.consecutiveFailures

	// A server that named a delay is obeyed rather than guessed at: it knows
	// when its own window resets, and the alternative is uncoordinated clients
	// backing off on disparate schedules and colliding again.
	wait := backoffFor(consecutive)
	var pushErr *ingest.PushError
	if errors.As(err, &pushErr) && pushErr.RetryAfter > 0 {
		wait = pushErr.RetryAfter
	}
	s.notBefore = time.Now().Add(wait)
	s.mu.Unlock()

	if s.onOutcome != nil {
		s.onOutcome(s.repoPath, classifyPushFailure(err, consecutive))
	}
}

// waitForBackoff blocks until this repo may attempt again, or until it is
// stopped. Reports false when the syncer should give up on this run entirely.
func (s *repoSyncer) waitForBackoff() bool {
	s.mu.Lock()
	wait := time.Until(s.notBefore)
	s.mu.Unlock()
	if wait <= 0 {
		return true
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-s.stop:
		return false
	}
}

// takeGrants returns and clears the wraps waiting to be sent.
func (s *repoSyncer) takeGrants() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	grants := s.pendingGrants
	s.pendingGrants = nil
	return grants
}

// recordGrants wraps MCK for each reader key the server reported pending, and
// reports whether anything is now waiting to go up.
//
// Wrapping happens here rather than at push time so a failure to wrap one
// device's key -- a malformed point, say -- costs that device and not the
// whole snapshot.
func (s *repoSyncer) recordGrants(pending []ingest.PendingGrant) bool {
	if len(pending) == 0 {
		return false
	}
	wrapped := make(map[string]string, len(pending))
	for _, grant := range pending {
		envelope, err := crypto.WrapMachineKey(s.identity, grant.ReaderKeyID, grant.PublicKey)
		if err != nil {
			log.Printf("treehouse: could not wrap machine key for reader %s: %v", grant.ReaderKeyID, err)
			continue
		}
		wrapped[grant.ReaderKeyID] = envelope
	}
	if len(wrapped) == 0 {
		return false
	}
	s.mu.Lock()
	if s.pendingGrants == nil {
		s.pendingGrants = wrapped
	} else {
		for id, envelope := range wrapped {
			s.pendingGrants[id] = envelope
		}
	}
	s.mu.Unlock()
	return true
}

func newRepoSyncer(apiGatewayURL, token, machineName, repoPath string, identity *crypto.Identity, stop <-chan struct{}) *repoSyncer {
	s := &repoSyncer{
		apiGatewayURL: apiGatewayURL,
		token:         token,
		machineName:   machineName,
		repoPath:      repoPath,
		identity:      identity,
		stop:          stop,
	}
	s.syncFn = s.sync
	return s
}

// Trigger returns immediately. It starts a sync if none is running, and
// otherwise marks one as owed so the in-flight run repeats once it finishes.
func (s *repoSyncer) Trigger() {
	s.mu.Lock()
	if s.running {
		s.pending = true
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	go s.run()
}

func (s *repoSyncer) run() {
	for {
		// Held off before the attempt, not after it, so a trigger arriving
		// during a backoff is coalesced into the one delayed run rather than
		// each becoming its own.
		if !s.waitForBackoff() {
			s.mu.Lock()
			s.running, s.pending = false, false
			s.mu.Unlock()
			return
		}

		err := s.syncFn()
		s.noteResult(err)
		if err != nil {
			log.Printf("treehouse: sync failed for %s: %v", s.repoPath, err)
		}

		s.mu.Lock()
		if !s.pending {
			s.running = false
			s.mu.Unlock()
			return
		}
		s.pending = false
		s.mu.Unlock()
	}
}

// buildSnapshot reads the repo's current state off disk. It is the expensive
// half of a sync and runs on every heartbeat regardless -- fsnotify can drop
// events, so "nothing changed" has to be established by looking, not assumed.
// What the heartbeat avoids is *uploading* the result again; see sync.
// grants ride the envelope so the sealing loop measures the body that will
// actually be sent. They are small -- a response caps pending grants, and each
// wrap is a few hundred bytes -- but the rule is measure the request, not an
// approximation of it, and a snapshot sitting just under the transport cap
// would otherwise fail in Push instead of shedding a patch.
func buildSnapshot(
	machineName string,
	identity *crypto.Identity,
	repoPath string,
	grants map[string]string,
) (ingest.RepoSnapshotPayload, error) {
	var snapshot ingest.RepoSnapshotPayload

	worktreePaths, err := git.ListWorktrees(repoPath)
	if err != nil {
		return snapshot, err
	}

	statuses := make([]*git.WorktreeStatus, 0, len(worktreePaths))
	changes := make([]payload.WorktreeChanges, 0, len(worktreePaths))
	for _, wtPath := range worktreePaths {
		ws, fileChanges, err := git.Status(wtPath)
		if err != nil {
			log.Printf("treehouse: status failed for worktree %s: %v", wtPath, err)
			continue
		}
		statuses = append(statuses, ws)
		changes = append(changes, payload.WorktreeChanges{Path: wtPath, Changes: fileChanges})
	}

	// A snapshot's worktree list is authoritative: the server replaces the
	// stored array with it wholesale. Publishing an empty list because every
	// status call happened to fail would therefore erase a repo the user can
	// still see on disk, so treat a total failure as "nothing to report yet"
	// and let the next sync recover. A repo that genuinely has no worktrees
	// reports zero paths above and never reaches here.
	if len(statuses) == 0 && len(worktreePaths) > 0 {
		return snapshot, fmt.Errorf("no worktree status could be read for %s", repoPath)
	}

	// Two passes, in this order. payload.Apply is the cheap plaintext one --
	// per-file and per-snapshot budgets over text we can measure directly --
	// and it binds first in normal operation. SealWorktrees then enforces what
	// the server actually measures, re-sealing between drops because nothing
	// about a file's plaintext size predicts how much ciphertext it adds.
	//
	// Both are applied once over the whole snapshot, not per worktree: the
	// budget has to hold for the single POST that carries all of them.
	limited := payload.Apply(changes)

	// The envelope is filled in first so the sealing loop can measure the real
	// encoded body, not just the ciphertext: paths and names are part of what
	// the transport cap bounds.
	snapshot.MachineInstanceID = identity.InstanceID.String()
	snapshot.MachineName = machineName
	snapshot.RepoPath = repoPath
	snapshot.RepoName = filepath.Base(repoPath)
	snapshot.Grants = grants

	worktrees, err := ingest.SealWorktrees(identity, repoPath, statuses, limited, snapshot)
	if err != nil {
		return snapshot, err
	}
	snapshot.Worktrees = worktrees
	return snapshot, nil
}

// snapshotStructure covers everything the server stores durably about a repo.
// Content tokens alone are not enough to justify a lean push: a plain `git
// fetch` moves ahead/behind without touching a single file, and that has to
// reach the durable row.
func snapshotStructure(snapshot ingest.RepoSnapshotPayload) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00", snapshot.RepoName)
	for _, wt := range snapshot.Worktrees {
		fmt.Fprintf(h, "%s\x00%s\x00%d\x00%d\x00%t\x00", wt.Path, wt.Branch, wt.Ahead, wt.Behind, wt.IsDirty)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// canSendLean reports whether this snapshot is identical, in every respect
// the server stores, to the last one we successfully pushed.
func (s *repoSyncer) canSendLean(snapshot ingest.RepoSnapshotPayload) bool {
	if len(s.lastPushed) == 0 || len(s.lastPushed) != len(snapshot.Worktrees) {
		return false
	}
	if s.lastStructure != snapshotStructure(snapshot) {
		return false
	}
	for _, wt := range snapshot.Worktrees {
		if wt.ContentToken == "" || s.lastPushed[wt.Path] != wt.ContentToken {
			return false
		}
	}
	return true
}

func (s *repoSyncer) remember(snapshot ingest.RepoSnapshotPayload) {
	pushed := make(map[string]string, len(snapshot.Worktrees))
	for _, wt := range snapshot.Worktrees {
		pushed[wt.Path] = wt.ContentToken
	}
	s.lastPushed = pushed
	s.lastStructure = snapshotStructure(snapshot)
}

// sync builds the current snapshot and pushes it, sending the lean form when
// nothing the server stores has moved since our last successful push. In the
// steady state -- an idle repo on the five-minute heartbeat -- that is a few
// hundred bytes instead of every patch in the repo re-uploaded unchanged.
//
// The server can refuse the shortcut: if its cache can no longer back our
// claim (an evicted payload or cache invalidation) it answers ResyncRequired and
// we immediately send the whole thing.
func (s *repoSyncer) sync() error {
	// Any wraps produced by the previous response ride this push. Taken before
	// the snapshot is built, so the sealing loop measures a body that includes
	// them, and before the lean check because a heartbeat carrying grants is
	// worth sending even though nothing else about the repo moved.
	grants := s.takeGrants()

	snapshot, err := buildSnapshot(s.machineName, s.identity, s.repoPath, grants)
	if err != nil {
		// Nothing was sent, so the wraps go back rather than being lost to a
		// failure that had nothing to do with them.
		s.restoreGrants(grants)
		return err
	}

	if len(grants) == 0 && s.canSendLean(snapshot) {
		lean := snapshot.Lean()
		result, err := ingest.Push(s.apiGatewayURL, s.token, lean)
		if err != nil {
			return err
		}
		if s.recordGrants(result.PendingGrants) {
			// A new device is waiting on this machine and the wrap is already
			// done, so send it now instead of on the next heartbeat. Without
			// this the reader waits two heartbeats -- one to learn the key
			// exists, one to deliver the wrap -- against a promise of one.
			s.Trigger()
		}
		if !result.ResyncRequired {
			return nil
		}
		log.Printf("treehouse: server requested a full resync of %s", s.repoPath)
		// Wraps that arrived on the lean response, which the snapshot was
		// therefore not measured with. Push's transport check still guards the
		// body, and a failure there restores them below -- so the next sync
		// takes them at the top and measures with them included.
		//
		// Assigned to grants as well, not just onto the snapshot: the failure
		// handler restores from grants, and without this the wraps taken here
		// are dropped when the full push fails.
		grants = s.takeGrants()
		snapshot.Grants = grants
	}

	result, err := ingest.Push(s.apiGatewayURL, s.token, snapshot)
	if err != nil {
		// The wraps did not land, so put them back rather than dropping them:
		// the server would otherwise keep reporting the same devices pending
		// and this machine would keep re-wrapping them every heartbeat.
		s.restoreGrants(grants)
		return err
	}
	if s.recordGrants(result.PendingGrants) {
		s.Trigger()
	}
	s.remember(snapshot)
	return nil
}

// restoreGrants puts wraps back after a failed push, without clobbering any
// that arrived in the meantime.
func (s *repoSyncer) restoreGrants(grants map[string]string) {
	if len(grants) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingGrants == nil {
		s.pendingGrants = grants
		return
	}
	for id, envelope := range grants {
		if _, newer := s.pendingGrants[id]; !newer {
			s.pendingGrants[id] = envelope
		}
	}
}
