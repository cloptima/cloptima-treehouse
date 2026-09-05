//go:build !unix

package config

import "os"

// The daemon is released for darwin and linux only, so there is no file-lock
// implementation here. These keep `go build` working on other platforms; a
// build that reaches them simply does not enforce single-instance.
func tryLockExclusive(_ *os.File) error { return nil }

func releaseLock(_ *os.File) {}
