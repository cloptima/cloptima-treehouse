// Package config persists the list of repos the daemon watches
// (explicit `treehouse add`, avoiding unrequested filesystem scans).
package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	EnvConfigPath = "TREEHOUSE_CONFIG_PATH"
	ConfigDirName = ".treehouse"
	ConfigName    = "config.json"
)

type Config struct {
	// APIGatewayURL defaults to https://api.cloptima.ai; overridable for dev.
	APIGatewayURL string `json:"api_gateway_url,omitempty"`
	MachineName   string `json:"machine_name,omitempty"`
	// LaunchAtLogin records whether the menu bar app should start at login.
	// A pointer so an absent key (first run) is distinguishable from an
	// explicit false: the daemon defaults a fresh install to on, but a
	// user's opt-out must stick.
	LaunchAtLogin *bool    `json:"launch_at_login,omitempty"`
	Repos         []string `json:"repos"`
}

// LaunchAtLoginPreference returns the saved preference and whether the user
// has one yet. Absent (false) means first run -- the caller defaults it on.
func (c *Config) LaunchAtLoginPreference() (enabled bool, set bool) {
	if c == nil || c.LaunchAtLogin == nil {
		return false, false
	}
	return *c.LaunchAtLogin, true
}

// SetLaunchAtLogin records an explicit preference.
func (c *Config) SetLaunchAtLogin(enabled bool) {
	c.LaunchAtLogin = &enabled
}

func defaultConfigPath() (string, error) {
	if path := strings.TrimSpace(os.Getenv(EnvConfigPath)); path != "" {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ConfigDirName, ConfigName), nil
}

func Load() (*Config, error) {
	path, err := defaultConfigPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func Save(cfg *Config) error {
	path, err := defaultConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// AddRepo registers one repo path, deduplicated, sorted for stable output.
func (c *Config) AddRepo(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	for _, existing := range c.Repos {
		if existing == abs {
			return false
		}
	}
	c.Repos = append(c.Repos, abs)
	sort.Strings(c.Repos)
	return true
}
