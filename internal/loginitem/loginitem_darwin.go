//go:build darwin && cgo

// Package loginitem manages whether Treehouse.app launches when the user logs
// in, via Apple's SMAppService (macOS 13+). It only makes sense for the menu
// bar app build: the Homebrew formula's bare binary has no bundle for
// SMAppService to register.
package loginitem

/*
#cgo CFLAGS: -x objective-c -fobjc-arc -mmacosx-version-min=13.0
#cgo LDFLAGS: -framework Foundation -framework ServiceManagement
#include <stdlib.h>
#include "shim_darwin.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// Status mirrors SMAppServiceStatus.
type Status int

const (
	StatusUnknown          Status = -1
	StatusNotRegistered    Status = C.TH_LOGIN_ITEM_NOT_REGISTERED
	StatusEnabled          Status = C.TH_LOGIN_ITEM_ENABLED
	StatusRequiresApproval Status = C.TH_LOGIN_ITEM_REQUIRES_APPROVAL
	StatusNotFound         Status = C.TH_LOGIN_ITEM_NOT_FOUND
)

// Supported reports whether this build can manage the login item. Always true
// on a darwin+cgo build; the OS-version floor is enforced by the app's
// LSMinimumSystemVersion and re-checked inside the shim.
func Supported() bool { return true }

func run(fn func(**C.char) C.int) error {
	var cErr *C.char
	if rc := fn(&cErr); rc != 0 {
		if cErr != nil {
			defer C.free(unsafe.Pointer(cErr))
			return errors.New(C.GoString(cErr))
		}
		return errors.New("login item operation failed")
	}
	return nil
}

// Register adds Treehouse.app to the user's Login Items.
func Register() error {
	return run(func(e **C.char) C.int { return C.th_login_item_register(e) })
}

// Unregister removes it.
func Unregister() error {
	return run(func(e **C.char) C.int { return C.th_login_item_unregister(e) })
}

// CurrentStatus reports SMAppService's view of the main-app login item.
func CurrentStatus() Status {
	return Status(C.th_login_item_status())
}
