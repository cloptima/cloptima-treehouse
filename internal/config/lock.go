package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// LockName sits beside config.json because the lock guards the same thing the
// config describes: one machine's watched repos, synced by one daemon.
const LockName = "daemon.lock"

// errLockHeld is what a platform's tryLockExclusive returns when the lock is
// already taken, as opposed to failing outright. Only this file turns it into
// the exported error.
var errLockHeld = errors.New("lock held")

// ErrDaemonRunning reports that another daemon already holds the lock. It
// carries that daemon's pid, which is the only useful thing to tell someone
// who now has to go find it.
type ErrDaemonRunning struct {
	PID int
}

func (e *ErrDaemonRunning) Error() string {
	if e.PID > 0 {
		return fmt.Sprintf("another treehouse daemon is already running (pid %d)", e.PID)
	}
	return "another treehouse daemon is already running"
}

func lockPath() (string, error) {
	configPath, err := defaultConfigPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(configPath), LockName), nil
}

// AcquireDaemonLock takes an exclusive lock for this machine's daemon and
// returns the function that releases it.
//
// Two daemons watching one machine is a real possibility now that Treehouse
// installs two ways: the cask's menu bar app and the formula's headless
// binary are the same daemon under the same machine name, reading the same
// config. Both running means every repo is watched twice and every heartbeat
// is sent twice -- wasteful rather than corrupting, since an unchanged
// snapshot is dropped server-side, but there is no reason to allow it.
//
// A file lock rather than a bare pid file: the lock belongs to the open file
// descriptor, so it is released whether the daemon exits cleanly, is killed,
// or panics. A pid file left behind by a crash would need its own staleness
// heuristic, and that heuristic is what usually breaks.
func AcquireDaemonLock() (func() error, error) {
	path, err := lockPath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create treehouse directory: %w", err)
	}

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open daemon lock: %w", err)
	}

	if err := tryLockExclusive(file); err != nil {
		// The pid is read only for the message, and only after the lock has
		// already been refused -- it is never what decides that.
		holder := readHolderPID(file)
		_ = file.Close()
		if errors.Is(err, errLockHeld) {
			return nil, &ErrDaemonRunning{PID: holder}
		}
		return nil, fmt.Errorf("lock daemon lock file: %w", err)
	}

	// Recorded after the lock is held, so what is in the file always belongs
	// to whoever currently owns it.
	if err := writeHolderPID(file); err != nil {
		releaseLock(file)
		_ = file.Close()
		return nil, err
	}

	return func() error {
		// Released explicitly so the intent is visible; closing the file would
		// do it anyway, which is what makes a crash safe.
		releaseLock(file)
		return file.Close()
	}, nil
}

func writeHolderPID(file *os.File) error {
	if err := file.Truncate(0); err != nil {
		return fmt.Errorf("reset daemon lock: %w", err)
	}
	if _, err := file.WriteAt([]byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		return fmt.Errorf("record daemon pid: %w", err)
	}
	return nil
}

func readHolderPID(file *os.File) int {
	buf := make([]byte, 32)
	n, err := file.ReadAt(buf, 0)
	if n == 0 && err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(buf[:n])))
	if err != nil {
		return 0
	}
	return pid
}
