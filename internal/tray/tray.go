package tray

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Options configures the menu bar tray lifecycle.
type Options struct {
	Version       string
	APIGatewayURL string
	WebURL        string
	Repos         []string
	Authenticated bool
	OnSyncNow     func()
	OnAddRepo     func()
	OnLogin       func()
	OnQuit        func()

	// LaunchAtLoginChecked is the initial state of the "Launch at Login"
	// checkbox. OnToggleLaunchAtLogin handles a click and returns the state
	// the checkbox should then show (the requested state on success, or the
	// state actually in effect on failure). A nil OnToggleLaunchAtLogin hides
	// the item entirely -- used on builds that cannot manage the login item.
	LaunchAtLoginChecked  bool
	OnToggleLaunchAtLogin func(enable bool) bool
}

// Controller allows the running daemon to update tray state dynamically.
type Controller interface {
	SetStatus(status string)
	// SetProblem puts a short marker in the menu bar itself, beside the icon,
	// and clears it when passed "".
	//
	// The status item above is inside the dropdown, so a daemon that had
	// stopped syncing said so only to someone who already suspected it and
	// clicked. A revoked token, a machine over its plan's limit, or a repo
	// failing every push are all conditions the person has to act on and
	// cannot otherwise discover -- so they belong where they are visible
	// without a click. Nothing is shown while syncing is healthy: a
	// permanent badge is noise, and noise is what stops people reading it.
	SetProblem(problem string)
	SetRepos(repos []string)
	SetAuthenticated(authenticated bool)
	SetUpdateAvailable(version, url string)
	Quit()
}

// ResolveWebURL derives the user-facing Treehouse web application URL from the
// configured API gateway URL.
func ResolveWebURL(apiGatewayURL string) string {
	switch {
	case strings.Contains(apiGatewayURL, "api.cloptima.ai"):
		return "https://treehouse.cloptima.ai"
	case strings.Contains(apiGatewayURL, "localhost") || strings.Contains(apiGatewayURL, "127.0.0.1"):
		return "http://localhost:3000"
	default:
		return "https://treehouse.cloptima.ai"
	}
}

// OpenBrowser launches the given URL in the user's default browser.
func OpenBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("open", url).Start()
	}
}

// appleScriptUserCancelled is AppleScript's "User Cancelled" error (-128),
// which `choose folder` raises when the dialog is dismissed. osascript
// reports it on stderr and exits non-zero, exactly like a real failure.
const appleScriptUserCancelled = "-128"

// PromptChooseFolder opens a native macOS Finder folder selection dialog.
// Returns the absolute path of the selected folder, or "" if cancelled.
//
// A cancel and a failure are reported differently on purpose: treating every
// non-zero exit as a cancel means a denied Automation permission, or a
// missing osascript, silently does nothing at all when the user clicks Add
// Repository -- the one failure mode where saying nothing is worst, because
// the user has no way to tell the click registered.
func PromptChooseFolder() (string, error) {
	if runtime.GOOS != "darwin" {
		return "", nil
	}
	cmd := exec.Command("osascript",
		"-e", "on run argv",
		"-e", "return POSIX path of (choose folder with prompt (item 1 of argv))",
		"-e", "end run",
		"Select a Git repository to watch in Treehouse:")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if strings.Contains(stderr.String(), appleScriptUserCancelled) {
			return "", nil
		}
		return "", fmt.Errorf("choose folder: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// appIconBundleMarker mirrors bundleMarker in tray_darwin.go (kept separate
// so this file, which has no build tag, never redeclares a name that file
// also defines when both are compiled together).
const appIconBundleMarker = ".app/Contents/MacOS/"

// treehouseIconPath resolves Treehouse.app's own icon from the running
// executable's location, so native prompts can carry it instead of a
// generic default. Empty when not running from the app bundle (e.g. the
// Homebrew formula's bare binary) or off Darwin -- callers fall back to a
// system icon.
func treehouseIconPath() string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	iconPath := bundledIconPath(exe)
	if iconPath == "" {
		return ""
	}
	if _, err := os.Stat(iconPath); err != nil {
		return ""
	}
	return iconPath
}

// bundledIconPath computes Treehouse.app's icon path from an executable
// path. Split out from treehouseIconPath so it can be tested against the
// paths each install method actually produces, rather than only against
// wherever the test binary happens to live.
func bundledIconPath(exe string) string {
	slashed := filepath.ToSlash(exe)
	idx := strings.Index(slashed, appIconBundleMarker)
	if idx < 0 {
		return ""
	}
	return filepath.FromSlash(slashed[:idx]) + ".app/Contents/Resources/AppIcon.icns"
}

// dialogIconClause is the `with icon ...` clause for a `display dialog`
// script: Treehouse's own icon when resolvable, a plain system icon
// otherwise.
func dialogIconClause() string {
	if path := treehouseIconPath(); path != "" {
		return fmt.Sprintf("with icon (POSIX file %q)", path)
	}
	return "with icon caution"
}

// ShowAlert displays a native, Treehouse-branded alert dialog on macOS using
// positional argv. Uses `display dialog` rather than `display alert`:
// AppleScript's alert has no custom-icon support, so run via plain osascript
// it shows a generic icon and no indication the prompt came from Treehouse
// at all -- `display dialog` supports both a custom icon and a window
// title, which is where that identity belongs.
func ShowAlert(title, message string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	script := fmt.Sprintf(
		`display dialog (item 1 of argv) with title "Treehouse" %s buttons {"OK"} default button "OK"`,
		dialogIconClause(),
	)
	return exec.Command("osascript",
		"-e", "on run argv",
		"-e", script,
		"-e", "end run",
		title+"\n\n"+message).Run()
}

// ShowNotification triggers a native macOS notification banner using positional argv.
func ShowNotification(title, message string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}
	return exec.Command("osascript",
		"-e", "on run argv",
		"-e", "display notification (item 1 of argv) with title (item 2 of argv)",
		"-e", "end run",
		message, title).Run()
}

const loginPromptButton = "Log In"

// ShowLoginPrompt asks, via a native two-button alert, whether to log in now.
// Used at startup so a signed-out launch doesn't sit silent in the menu bar
// until someone happens to open it. Returns true if the user chose to log in.
func ShowLoginPrompt(title, message string) (bool, error) {
	if runtime.GOOS != "darwin" {
		return false, nil
	}
	script := fmt.Sprintf(
		`display dialog (item 1 of argv) with title "Treehouse" %s buttons {"Not Now", "Log In"} default button "Log In"`,
		dialogIconClause(),
	)
	out, err := exec.Command("osascript",
		"-e", "on run argv",
		"-e", script,
		"-e", "end run",
		title+"\n\n"+message).Output()
	if err != nil {
		// User cancelled (Esc / window close) counts as "not now", not a failure.
		return false, nil
	}
	return loginChosen(string(out)), nil
}

func loginChosen(osascriptOutput string) bool {
	return strings.Contains(osascriptOutput, "button returned:"+loginPromptButton)
}
