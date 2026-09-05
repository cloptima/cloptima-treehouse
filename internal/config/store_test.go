package config

import (
	"path/filepath"
	"testing"
)

func TestLaunchAtLoginPreference(t *testing.T) {
	var unset Config
	if enabled, set := unset.LaunchAtLoginPreference(); set || enabled {
		t.Fatalf("absent key: got (enabled=%v, set=%v), want (false, false)", enabled, set)
	}

	unset.SetLaunchAtLogin(false)
	if enabled, set := unset.LaunchAtLoginPreference(); !set || enabled {
		t.Fatalf("explicit false: got (enabled=%v, set=%v), want (false, true)", enabled, set)
	}

	unset.SetLaunchAtLogin(true)
	if enabled, set := unset.LaunchAtLoginPreference(); !set || !enabled {
		t.Fatalf("explicit true: got (enabled=%v, set=%v), want (true, true)", enabled, set)
	}
}

func TestLaunchAtLoginRoundTripsThroughDisk(t *testing.T) {
	t.Setenv(EnvConfigPath, filepath.Join(t.TempDir(), "config.json"))

	saved := &Config{Repos: []string{"/repo/a"}}
	saved.SetLaunchAtLogin(false)
	if err := Save(saved); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	enabled, set := loaded.LaunchAtLoginPreference()
	if !set || enabled {
		t.Fatalf("after round trip: got (enabled=%v, set=%v), want (false, true)", enabled, set)
	}
}

func TestLaunchAtLoginAbsentWhenNeverSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv(EnvConfigPath, path)

	if err := Save(&Config{Repos: []string{"/repo/a"}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, set := loaded.LaunchAtLoginPreference(); set {
		t.Fatal("launch_at_login should be absent when never set, so first-run default-on still applies")
	}
}
