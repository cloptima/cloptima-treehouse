package tray

import (
	_ "embed"
)

//go:embed assets/icon_16.png
var icon16 []byte

//go:embed assets/icon_32.png
var icon32 []byte

func TrayIcon16() []byte {
	return icon16
}

func TrayIcon32() []byte {
	return icon32
}
