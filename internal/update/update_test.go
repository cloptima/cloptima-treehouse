package update

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func withReleases(t *testing.T, body string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	original := releasesURL
	releasesURL = server.URL
	t.Cleanup(func() { releasesURL = original })
}

const mixedReleases = `[
	{"tag_name": "treehouse-v0.3.0", "html_url": "https://example.com/treehouse-v0.3.0"},
	{"tag_name": "other-tool-v9.9.9", "html_url": "https://example.com/other-tool-v9.9.9"},
	{"tag_name": "treehouse-v0.2.0", "html_url": "https://example.com/treehouse-v0.2.0"},
	{"tag_name": "treehouse-v0.1.0", "html_url": "https://example.com/treehouse-v0.1.0"}
]`

func TestCheckReportsNewerVersionIgnoringOtherTools(t *testing.T) {
	withReleases(t, mixedReleases)

	info, err := Check("0.1.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.Available {
		t.Fatal("expected an update to be available")
	}
	if info.Version != "0.3.0" {
		t.Errorf("expected latest version 0.3.0, got %q", info.Version)
	}
	if info.URL != "https://example.com/treehouse-v0.3.0" {
		t.Errorf("unexpected URL: %q", info.URL)
	}
}

func TestCheckReportsNothingWhenAlreadyLatest(t *testing.T) {
	withReleases(t, mixedReleases)

	info, err := Check("0.3.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Available {
		t.Errorf("expected no update, got %+v", info)
	}
}

func TestCheckReportsNothingWhenRunningNewerThanAnyRelease(t *testing.T) {
	withReleases(t, mixedReleases)

	info, err := Check("9.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Available {
		t.Errorf("expected no update for a version ahead of every release, got %+v", info)
	}
}

func TestCheckSkipsDevBuilds(t *testing.T) {
	withReleases(t, mixedReleases)

	for _, v := range []string{"", "dev"} {
		info, err := Check(v)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", v, err)
		}
		if info.Available {
			t.Errorf("expected dev build %q to skip the check, got %+v", v, info)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int // sign only
	}{
		{"0.2.0", "0.1.0", 1},
		{"0.1.0", "0.2.0", -1},
		{"1.0.0", "1.0.0", 0},
		{"0.10.0", "0.9.0", 1}, // numeric, not lexical, comparison
		{"0.1.0-beta.1", "0.1.0", 0},
	}
	for _, tt := range tests {
		got := compareVersions(tt.a, tt.b)
		switch {
		case tt.want > 0 && got <= 0:
			t.Errorf("compareVersions(%q, %q) = %d, want > 0", tt.a, tt.b, got)
		case tt.want < 0 && got >= 0:
			t.Errorf("compareVersions(%q, %q) = %d, want < 0", tt.a, tt.b, got)
		case tt.want == 0 && got != 0:
			t.Errorf("compareVersions(%q, %q) = %d, want 0", tt.a, tt.b, got)
		}
	}
}
