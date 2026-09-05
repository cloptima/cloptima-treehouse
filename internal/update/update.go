// Package update checks whether a newer Treehouse release exists, so the
// tray can surface it. It only checks and reports -- installing a new
// version is left to the user (via Homebrew) or a future auto-updater.
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// releasesURL is a var, not a const, so tests can point it at a local
// httptest server instead of the real GitHub API.
var releasesURL = "https://api.github.com/repos/cloptima/cloptima-treehouse/releases"

func parseReleaseVersion(tag string) (string, bool) {
	if v, ok := strings.CutPrefix(tag, "treehouse-v"); ok {
		return v, true
	}
	if v, ok := strings.CutPrefix(tag, "v"); ok {
		return v, true
	}
	return "", false
}

const requestTimeout = 10 * time.Second

type release struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

// Info describes the result of a version check.
type Info struct {
	Available bool
	Version   string
	URL       string
}

// Check compares currentVersion against the newest published Treehouse
// release and reports whether a newer one exists. A dev build ("" or "dev",
// what cli.version defaults to unset) never reports an update -- there is no
// meaningful version to compare against.
func Check(currentVersion string) (Info, error) {
	if currentVersion == "" || currentVersion == "dev" {
		return Info{}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releasesURL, nil)
	if err != nil {
		return Info{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Info{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Info{}, fmt.Errorf("github releases: %s", resp.Status)
	}

	var releases []release
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return Info{}, err
	}

	var latestVersion, latestURL string
	for _, r := range releases {
		v, ok := parseReleaseVersion(r.TagName)
		if !ok {
			continue
		}
		if latestVersion == "" || compareVersions(v, latestVersion) > 0 {
			latestVersion, latestURL = v, r.HTMLURL
		}
	}
	if latestVersion == "" || compareVersions(latestVersion, currentVersion) <= 0 {
		return Info{}, nil
	}
	return Info{Available: true, Version: latestVersion, URL: latestURL}, nil
}

// compareVersions orders two dotted major.minor.patch versions (the release
// workflow's own format, optionally with a "-pre.release" suffix this
// ignores for ordering purposes). Returns >0 if a > b, <0 if a < b, 0 if
// equal or either side is unparseable.
func compareVersions(a, b string) int {
	pa, pb := versionCore(a), versionCore(b)
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] - pb[i]
		}
	}
	return 0
}

func versionCore(v string) [3]int {
	core, _, _ := strings.Cut(v, "-")
	parts := strings.SplitN(core, ".", 3)
	var out [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		n, _ := strconv.Atoi(parts[i])
		out[i] = n
	}
	return out
}
