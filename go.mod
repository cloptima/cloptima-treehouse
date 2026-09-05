module github.com/cloptima/cloptima-treehouse

go 1.25.7

require (
	github.com/fsnotify/fsnotify v1.9.0
	// Imported directly by internal/tray/tray_darwin.go, which builds only
	// under `darwin && cgo && !notray` -- `go mod tidy` run on any other
	// platform cannot see that import and demotes this to indirect.
	github.com/getlantern/systray v1.2.2
	github.com/spf13/cobra v1.10.1
	github.com/zalando/go-keyring v0.2.6
)

require (
	github.com/google/uuid v1.6.0
	rsc.io/qr v0.2.0
)

require (
	al.essio.dev/pkg/shellescape v1.5.1 // indirect
	github.com/danieljoos/wincred v1.2.2 // indirect
	github.com/getlantern/context v0.0.0-20190109183933-c447772a6520 // indirect
	github.com/getlantern/errors v0.0.0-20190325191628-abdb3e3e36f7 // indirect
	github.com/getlantern/golog v0.0.0-20190830074920-4ef2e798c2d7 // indirect
	github.com/getlantern/hex v0.0.0-20190417191902-c6586a6fe0b7 // indirect
	github.com/getlantern/hidden v0.0.0-20190325191715-f02dbb02be55 // indirect
	github.com/getlantern/ops v0.0.0-20190325191751-d70cb0d6f85f // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/oxtoacart/bpool v0.0.0-20190530202638-03653db5a59c // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/sys v0.26.0 // indirect
)
