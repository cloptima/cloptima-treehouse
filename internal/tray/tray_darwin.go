//go:build darwin && cgo && !notray

package tray

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/getlantern/systray"
)

// bundleMarker is the path segment every macOS application bundle puts its
// executable behind.
const bundleMarker = ".app/Contents/MacOS/"

// Available reports whether this process can actually own a menu bar item.
//
// macOS decides that from the application bundle, not from the code: a bare
// executable is launched as a BackgroundOnly process, and a BackgroundOnly
// process gets no status item however much AppKit it calls. The tar.gz that
// the Homebrew formula installs is exactly that bare executable, so the same
// binary has to run headless there and show a menu bar item when it is
// launched from Treehouse.app -- silently entering an event loop that can
// never draw anything just looks like a hang.
//
// Checked by path rather than by asking NSBundle for an identifier: it needs
// no cgo, and the layout it looks for is the one the release workflow builds.
// Symlinks are resolved first because Homebrew installs binaries as links.
func Available() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return isBundledPath(exe)
}

// isBundledPath is split out from Available so the decision can be tested
// against the paths each install method actually produces, rather than only
// against wherever the test binary happens to live.
func isBundledPath(exe string) bool {
	return strings.Contains(filepath.ToSlash(exe), bundleMarker)
}

// UnavailableNotice tells someone who ran the bare binary how to get the menu
// bar app, rather than leaving them to wonder where the icon went.
func UnavailableNotice() string {
	return "treehouse: running headless -- the menu bar app needs its application bundle.\n" +
		"  Install it with: brew install --cask cloptima/tap/treehouse"
}

type darwinController struct {
	mu        sync.Mutex
	mHeader   *systray.MenuItem
	mLogin    *systray.MenuItem
	mRepos    *systray.MenuItem
	mUpdate   *systray.MenuItem
	repoItems []*systray.MenuItem
	// repoPaths[i] is the full path repoItems[i] currently represents --
	// read by that item's own click handler at click time, not captured at
	// creation, since SetRepos reuses slots for different repos over time.
	repoPaths     []string
	repos         []string
	authenticated bool
	updateURL     string
	// problem is the marker currently in the menu bar, kept so a repeated
	// report of the same condition is not an AppKit call on every heartbeat.
	problem string
}

// watchRepoItemClicks opens Finder at whatever repo this slot currently
// represents.
func (c *darwinController) watchRepoItemClicks(idx int, item *systray.MenuItem) {
	for range item.ClickedCh {
		c.mu.Lock()
		path := c.repoPaths[idx]
		c.mu.Unlock()
		if path != "" {
			_ = OpenBrowser(path)
		}
	}
}

func (c *darwinController) SetStatus(status string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mHeader != nil {
		c.mHeader.SetTitle(status)
	}
}

// SetProblem writes the marker into the menu bar title, which is the only
// surface the user sees without opening the menu.
//
// systray.SetTitle is the whole mechanism: an empty title leaves the icon
// alone, so clearing is just setting it back. The text has to stay very short
// -- it sits in a bar the user has already filled with other apps, and macOS
// gives it no more room than it asks for.
func (c *darwinController) SetProblem(problem string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.problem == problem {
		return
	}
	c.problem = problem
	systray.SetTitle(problem)
	if problem == "" {
		systray.SetTooltip("Treehouse - Git sync daemon")
		return
	}
	systray.SetTooltip("Treehouse - " + problem)
}

func (c *darwinController) SetAuthenticated(authenticated bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authenticated = authenticated
	if c.mLogin != nil {
		if authenticated {
			c.mLogin.Hide()
		} else {
			c.mLogin.Show()
		}
	}
}

// SetRepos rewrites the watched-repository submenu in place. systray can hide
// a menu item but never remove one, so adding a fresh item per repo on every
// call would leave the old ones hidden-but-present forever, growing the menu
// by len(repos) each time a repository is added. Existing items are retitled
// and only the shortfall is created.
func (c *darwinController) SetRepos(repos []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.repos = repos
	if c.mRepos == nil {
		return
	}
	c.mRepos.SetTitle(fmt.Sprintf("Watched Repositories (%d)", len(repos)))
	for len(c.repoItems) < len(repos) {
		item := c.mRepos.AddSubMenuItem("", "")
		idx := len(c.repoItems)
		c.repoItems = append(c.repoItems, item)
		c.repoPaths = append(c.repoPaths, "")
		go c.watchRepoItemClicks(idx, item)
	}
	for i, item := range c.repoItems {
		if i < len(repos) {
			item.SetTitle(filepath.Base(repos[i]))
			item.SetTooltip(repos[i] + " (click to open in Finder)")
			c.repoPaths[i] = repos[i]
			item.Show()
			continue
		}
		item.Hide()
	}
}

// SetUpdateAvailable reveals the update item once a newer release exists.
// There is no path back to hidden -- a running process's own version never
// changes, so once this fires it stays true until the user updates and
// restarts.
func (c *darwinController) SetUpdateAvailable(version, url string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.updateURL = url
	if c.mUpdate != nil {
		c.mUpdate.SetTitle(fmt.Sprintf("Update Available (v%s)", version))
		c.mUpdate.Show()
	}
}

func (c *darwinController) Quit() {
	systray.Quit()
}

// Run launches the macOS menu bar tray item using Cocoa AppKit and executes
// startDaemon on a background goroutine once the menu is ready.
func Run(opts Options, startDaemon func(ctl Controller, stop <-chan struct{})) error {
	stop := make(chan struct{})
	var closeOnce sync.Once
	closeStop := func() {
		closeOnce.Do(func() {
			close(stop)
			if opts.OnQuit != nil {
				opts.OnQuit()
			}
		})
	}

	ctl := &darwinController{
		repos:         opts.Repos,
		authenticated: opts.Authenticated,
	}

	onReady := func() {
		if icon := TrayIcon16(); len(icon) > 0 {
			systray.SetTemplateIcon(icon, TrayIcon32())
		}
		systray.SetTooltip("Treehouse - Git sync daemon")

		var statusText string
		switch {
		case !opts.Authenticated:
			statusText = "Treehouse • Not Logged In"
		case len(opts.Repos) == 0:
			statusText = "Treehouse • Active (0 repos registered)"
		default:
			statusText = fmt.Sprintf("Treehouse • Active (Watching %d repos)", len(opts.Repos))
		}
		ctl.mHeader = systray.AddMenuItem(statusText, "Treehouse background status")
		ctl.mHeader.Disable()

		systray.AddSeparator()

		webURL := opts.WebURL
		if webURL == "" {
			webURL = ResolveWebURL(opts.APIGatewayURL)
		}
		ctl.mLogin = systray.AddMenuItem("Log In…", "Log in via browser OAuth")
		if opts.Authenticated {
			ctl.mLogin.Hide()
		}

		// Every handler runs on its own goroutine rather than inline. Login
		// blocks for up to three minutes waiting on the browser and the
		// folder picker blocks until the user dismisses it, so running them
		// on the loop below would leave Quit -- and every other item --
		// unresponsive for the duration.
		go func() {
			for range ctl.mLogin.ClickedCh {
				if opts.OnLogin != nil {
					go opts.OnLogin()
				} else {
					_ = OpenBrowser(webURL + "/login")
				}
			}
		}()
		mOpenWeb := systray.AddMenuItem("Open Web App", fmt.Sprintf("Open %s in browser", webURL))
		mSyncNow := systray.AddMenuItem("Sync Now", "Trigger immediate status/diff sync")
		mAddRepo := systray.AddMenuItem("Add Repository…", "Choose a Git repository folder to watch")

		ctl.mRepos = systray.AddMenuItem(fmt.Sprintf("Watched Repositories (%d)", len(opts.Repos)), "")
		ctl.repoItems = make([]*systray.MenuItem, 0, len(opts.Repos))
		ctl.repoPaths = make([]string, 0, len(opts.Repos))
		for _, repo := range opts.Repos {
			item := ctl.mRepos.AddSubMenuItem(filepath.Base(repo), repo+" (click to open in Finder)")
			idx := len(ctl.repoItems)
			ctl.repoItems = append(ctl.repoItems, item)
			ctl.repoPaths = append(ctl.repoPaths, repo)
			go ctl.watchRepoItemClicks(idx, item)
		}

		if opts.OnToggleLaunchAtLogin != nil {
			mLaunchAtLogin := systray.AddMenuItemCheckbox(
				"Launch at Login",
				"Start Treehouse automatically when you log in",
				opts.LaunchAtLoginChecked,
			)
			// systray does not toggle a checkbox on click -- the handler owns
			// that -- so the target state is the opposite of what it shows now,
			// and the callback's return value is what it should show after.
			go func() {
				for range mLaunchAtLogin.ClickedCh {
					if opts.OnToggleLaunchAtLogin(!mLaunchAtLogin.Checked()) {
						mLaunchAtLogin.Check()
					} else {
						mLaunchAtLogin.Uncheck()
					}
				}
			}()
		}

		systray.AddSeparator()

		ver := opts.Version
		if ver == "" {
			ver = "dev"
		}
		mVersion := systray.AddMenuItem(fmt.Sprintf("Treehouse v%s", ver), "Current version")
		mVersion.Disable()

		// Hidden until SetUpdateAvailable reveals it -- most launches have
		// nothing to report.
		ctl.mUpdate = systray.AddMenuItem("Update Available", "A newer version of Treehouse is available")
		ctl.mUpdate.Hide()

		mQuit := systray.AddMenuItem("Quit Treehouse", "Stop watching and quit")

		go func() {
			for {
				select {
				case <-mOpenWeb.ClickedCh:
					_ = OpenBrowser(webURL)
				case <-mSyncNow.ClickedCh:
					if opts.OnSyncNow != nil {
						go opts.OnSyncNow()
					}
				case <-mAddRepo.ClickedCh:
					if opts.OnAddRepo != nil {
						go opts.OnAddRepo()
					}
				case <-ctl.mUpdate.ClickedCh:
					ctl.mu.Lock()
					url := ctl.updateURL
					ctl.mu.Unlock()
					if url != "" {
						_ = OpenBrowser(url)
					}
				case <-mQuit.ClickedCh:
					systray.Quit()
					return
				}
			}
		}()

		go startDaemon(ctl, stop)
	}

	onExit := func() {
		closeStop()
	}

	systray.Run(onReady, onExit)
	return nil
}
