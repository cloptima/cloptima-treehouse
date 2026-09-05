//go:build unix

package config

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// withTempHome points the whole config package at a scratch directory, since
// the lock lives beside config.json.
func withTempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(EnvConfigPath, filepath.Join(dir, ConfigName))
	return dir
}

func TestDaemonLockIsReleasedAndReacquirable(t *testing.T) {
	withTempHome(t)

	release, err := AcquireDaemonLock()
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if err := release(); err != nil {
		t.Fatalf("release: %v", err)
	}

	release2, err := AcquireDaemonLock()
	if err != nil {
		t.Fatalf("a released lock must be retakeable, got %v", err)
	}
	_ = release2()
}

func TestDaemonLockRecordsTheHoldersPID(t *testing.T) {
	dir := withTempHome(t)

	release, err := AcquireDaemonLock()
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer func() { _ = release() }()

	raw, err := os.ReadFile(filepath.Join(dir, LockName))
	if err != nil {
		t.Fatalf("read lock file: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("lock file should hold a pid, got %q", raw)
	}
	if pid != os.Getpid() {
		t.Fatalf("expected this process's pid %d, got %d", os.Getpid(), pid)
	}
}

// The lock has to hold against a separate process, which is the only case
// that matters: flock is per-open-file-description, so a same-process
// re-acquire proves nothing about two daemons.
func TestDaemonLockBlocksAnotherProcess(t *testing.T) {
	dir := withTempHome(t)

	release, err := AcquireDaemonLock()
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer func() { _ = release() }()

	// Re-runs this test binary as a child, which takes the helper branch
	// below and reports whether it saw the lock as held.
	// -test.v so the helper's t.Logf actually reaches stdout.
	cmd := exec.Command(os.Args[0], "-test.run=TestDaemonLockHelperProcess", "-test.v")
	cmd.Env = append(os.Environ(),
		"TREEHOUSE_LOCK_HELPER=1",
		EnvConfigPath+"="+filepath.Join(dir, ConfigName),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper process failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "HELPER:blocked:"+strconv.Itoa(os.Getpid())) {
		t.Fatalf("a second process must be refused and told which pid holds it, got:\n%s", out)
	}
}

// TestDaemonLockHelperProcess is not a test; it is the child half of
// TestDaemonLockBlocksAnotherProcess and no-ops unless that parent invoked it.
func TestDaemonLockHelperProcess(t *testing.T) {
	if os.Getenv("TREEHOUSE_LOCK_HELPER") != "1" {
		t.Skip("helper process for TestDaemonLockBlocksAnotherProcess")
	}
	_, err := AcquireDaemonLock()
	var running *ErrDaemonRunning
	if errors.As(err, &running) {
		t.Logf("HELPER:blocked:%d", running.PID)
		return
	}
	t.Fatalf("expected the lock to be refused, got %v", err)
}

// A lock file left behind by a killed daemon must not wedge the next start:
// the kernel drops the flock when the holder's descriptor closes, so the
// leftover file is just stale bytes.
func TestDaemonLockIgnoresAStaleLockFile(t *testing.T) {
	dir := withTempHome(t)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, LockName), []byte("999999"), 0o600); err != nil {
		t.Fatalf("seed stale lock: %v", err)
	}

	release, err := AcquireDaemonLock()
	if err != nil {
		t.Fatalf("a stale lock file must not block startup, got %v", err)
	}
	_ = release()
}
