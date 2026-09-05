package loginitem

import "testing"

func TestUnsupportedBuildFailsClosed(t *testing.T) {
	if Supported() {
		t.Skip("darwin+cgo build: SMAppService integration is present")
	}
	if err := Register(); err == nil {
		t.Error("Register should report the feature is unavailable on this build")
	}
	if err := Unregister(); err == nil {
		t.Error("Unregister should report the feature is unavailable on this build")
	}
	if got := CurrentStatus(); got != StatusUnknown {
		t.Errorf("CurrentStatus() = %d, want StatusUnknown on an unsupported build", got)
	}
}

func TestSupportedBuildCanReadStatusWithoutPanicking(t *testing.T) {
	if !Supported() {
		t.Skip("not a darwin+cgo build")
	}
	// A unit-test binary is not an installed .app, so this is typically
	// StatusNotFound / StatusNotRegistered -- the point is only that reading
	// it neither panics nor blocks.
	_ = CurrentStatus()
}
