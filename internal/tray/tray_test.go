package tray

import (
	"bytes"
	"image/png"
	"testing"
)

func TestResolveWebURL(t *testing.T) {
	tests := []struct {
		apiURL   string
		expected string
	}{
		{"https://api.cloptima.ai", "https://treehouse.cloptima.ai"},
		{"http://localhost:8080", "http://localhost:3000"},
		{"http://127.0.0.1:8080", "http://localhost:3000"},
		{"", "https://treehouse.cloptima.ai"},
	}

	for _, tt := range tests {
		if got := ResolveWebURL(tt.apiURL); got != tt.expected {
			t.Errorf("ResolveWebURL(%q) = %q, want %q", tt.apiURL, got, tt.expected)
		}
	}
}

func TestBundledIconPath(t *testing.T) {
	tests := []struct {
		name     string
		exe      string
		expected string
	}{
		{
			name:     "cask install",
			exe:      "/Applications/Treehouse.app/Contents/MacOS/treehouse",
			expected: "/Applications/Treehouse.app/Contents/Resources/AppIcon.icns",
		},
		{
			name:     "formula install (bare binary, no bundle)",
			exe:      "/opt/homebrew/Cellar/treehouse-cli/0.1.0/bin/treehouse",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bundledIconPath(tt.exe); got != tt.expected {
				t.Errorf("bundledIconPath(%q) = %q, want %q", tt.exe, got, tt.expected)
			}
		})
	}
}

func TestLoginChosen(t *testing.T) {
	tests := []struct {
		output   string
		expected bool
	}{
		{"button returned:Log In", true},
		{"button returned:Not Now", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := loginChosen(tt.output); got != tt.expected {
			t.Errorf("loginChosen(%q) = %v, want %v", tt.output, got, tt.expected)
		}
	}
}

func TestTrayIconsGenerateValidPNG(t *testing.T) {
	icon16 := TrayIcon16()
	if len(icon16) == 0 {
		t.Fatal("expected non-empty icon16 bytes")
	}
	cfg16, err := png.DecodeConfig(bytes.NewReader(icon16))
	if err != nil {
		t.Fatalf("failed to decode icon16 png config: %v", err)
	}
	if cfg16.Width != 16 || cfg16.Height != 16 {
		t.Errorf("expected 16x16 icon, got %dx%d", cfg16.Width, cfg16.Height)
	}

	icon32 := TrayIcon32()
	if len(icon32) == 0 {
		t.Fatal("expected non-empty icon32 bytes")
	}
	cfg32, err := png.DecodeConfig(bytes.NewReader(icon32))
	if err != nil {
		t.Fatalf("failed to decode icon32 png config: %v", err)
	}
	if cfg32.Width != 32 || cfg32.Height != 32 {
		t.Errorf("expected 32x32 icon, got %dx%d", cfg32.Width, cfg32.Height)
	}
}
