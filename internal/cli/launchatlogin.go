package cli

import (
	"fmt"
	"log"

	"github.com/cloptima/cloptima-treehouse/internal/config"
	"github.com/cloptima/cloptima-treehouse/internal/loginitem"
	"github.com/cloptima/cloptima-treehouse/internal/tray"
)

// loginItemActive folds SMAppService's status into a yes/no. requiresApproval
// counts as active: the user has started enabling the item and only System
// Settings can finish, so treating it as off would make us re-register
// pointlessly.
func loginItemActive(s loginitem.Status) bool {
	return s == loginitem.StatusEnabled || s == loginitem.StatusRequiresApproval
}

// nudgeToApprove points the user at System Settings when the login item is
// registered but not yet approved to run. Takes the status the caller already
// read rather than querying again.
func nudgeToApprove(status loginitem.Status) {
	if status == loginitem.StatusRequiresApproval {
		_ = tray.ShowNotification("Treehouse", "Open System Settings > General > Login Items and turn Treehouse on to finish.")
	}
}

// launchAtLoginResolution is the pure decision reconcileLaunchAtLogin makes
// once it knows the current OS state (and, on a first run, whether the
// registration attempt failed). persist is nil when config should be left
// alone; show is the state the menu checkbox should display.
//
//   - First run, registration failed: record nothing, so the next launch from
//     a real install retries the default-on instead of inheriting a "user
//     opted out" it never chose.
//   - First run otherwise: the app is (now) registered -- record on.
//   - Already chosen once: the OS is the source of truth (the user may have
//     toggled it in System Settings), so adopt its state and rewrite config
//     to match when they differ.
func launchAtLoginResolution(saved, userSet, active, registerFailed bool) (persist *bool, show bool) {
	if !userSet {
		if registerFailed {
			return nil, false
		}
		on := true
		return &on, true
	}
	if active != saved {
		adopted := active
		return &adopted, active
	}
	return nil, active
}

// reconcileLaunchAtLogin brings the OS login item in line with the saved
// preference at startup and returns the state the "Launch at Login" menu
// checkbox should show. A fresh install has no saved preference, so it
// defaults to on: the app is registered and the choice persisted.
func reconcileLaunchAtLogin(cfg *config.Config) bool {
	saved, userSet := cfg.LaunchAtLoginPreference()
	active := loginItemActive(loginitem.CurrentStatus())
	registerFailed := false

	if !userSet && !active {
		if err := loginitem.Register(); err != nil {
			log.Printf("treehouse: could not enable Launch at Login on first run: %v", err)
			registerFailed = true
		} else {
			status := loginitem.CurrentStatus()
			active = loginItemActive(status)
			nudgeToApprove(status)
		}
	}

	persist, show := launchAtLoginResolution(saved, userSet, active, registerFailed)
	if persist != nil {
		persistLaunchAtLogin(cfg, *persist)
	}
	return show
}

func persistLaunchAtLogin(cfg *config.Config, enabled bool) {
	cfg.SetLaunchAtLogin(enabled)
	if err := config.Save(cfg); err != nil {
		log.Printf("treehouse: could not persist Launch at Login preference: %v", err)
	}
}

// applyLaunchAtLogin is the tray checkbox handler: it registers or
// unregisters the login item, persists whatever state the OS is actually in
// afterwards, and returns that state for the checkbox to show.
func applyLaunchAtLogin(enable bool) bool {
	var err error
	if enable {
		err = loginitem.Register()
	} else {
		err = loginitem.Unregister()
	}
	if err != nil {
		verb := "disable"
		if enable {
			verb = "enable"
		}
		_ = tray.ShowAlert("Launch at Login", fmt.Sprintf("Could not %s Launch at Login:\n\n%v", verb, err))
		return loginItemActive(loginitem.CurrentStatus())
	}

	status := loginitem.CurrentStatus()
	nowOn := loginItemActive(status)

	// Reload rather than reuse the daemon's startup copy: `treehouse add` and
	// the tray's Add Repository both rewrite this file, so a blind save here
	// could drop a repo registered since launch.
	if fresh, ferr := config.Load(); ferr != nil {
		log.Printf("treehouse: could not reload config to save Launch at Login: %v", ferr)
	} else {
		persistLaunchAtLogin(fresh, nowOn)
	}

	if enable {
		nudgeToApprove(status)
	}
	return nowOn
}
