//go:build !darwin || !cgo || notray

package tray

import "errors"

// Available is false on every non-macOS build and on a macOS build compiled
// without cgo or with the notray tag: there is no menu bar to put an item in.
// runDaemon runs headless instead, so Run is never reached.
func Available() bool { return false }

// UnavailableNotice is unused on these builds -- Available is false from the
// start, so runDaemon never claims a tray was expected.
func UnavailableNotice() string {
	return "treehouse: no menu bar on this platform; running headless."
}

// Run exists only to satisfy the call in runDaemon, which is guarded by
// Available. Reaching it means that guard was removed.
func Run(_ Options, _ func(ctl Controller, stop <-chan struct{})) error {
	return errors.New("menu bar tray is not available in this build")
}
