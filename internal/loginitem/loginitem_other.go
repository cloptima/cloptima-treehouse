//go:build !darwin || !cgo

package loginitem

import "errors"

// Status mirrors SMAppServiceStatus. The values match the darwin build so
// callers can share reconciliation logic across platforms.
type Status int

const (
	StatusUnknown          Status = -1
	StatusNotRegistered    Status = 0
	StatusEnabled          Status = 1
	StatusRequiresApproval Status = 2
	StatusNotFound         Status = 3
)

// ErrUnsupported is returned by Register/Unregister on any build without the
// macOS app's SMAppService integration (non-darwin, or darwin without cgo).
var ErrUnsupported = errors.New("launch at login is only available in the macOS app build")

// Supported reports whether this build can manage the login item.
func Supported() bool { return false }

// Register is a no-op that reports it is unsupported here.
func Register() error { return ErrUnsupported }

// Unregister is a no-op that reports it is unsupported here.
func Unregister() error { return ErrUnsupported }

// CurrentStatus is always StatusUnknown off the macOS app build.
func CurrentStatus() Status { return StatusUnknown }
