package auth

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The login flow carries this machine's stable identity so the minted token
// can be bound to it. A login without one is refused, because a token minted
// unbound cannot ingest at all.
const testInstanceID = "44444444-4444-4444-4444-444444444444"

// callback issues one request against the loopback listener the login flow
// just opened, the way the browser redirect does. It reports rather than
// fails, because every caller runs it from a goroutine and t.Fatal is only
// legal on the goroutine running the test.
func callback(port, state, token string) (int, error) {
	target := fmt.Sprintf("http://127.0.0.1:%s/callback?state=%s&token=%s",
		port, url.QueryEscape(state), url.QueryEscape(token))
	resp, err := http.Get(target)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, nil
}

// The handshake is driven end to end -- a real listener, a real redirect --
// rather than by re-implementing the handler in the test, which is what the
// previous version of this file did and which could not have caught a change
// to the handler itself.
func TestRequestTokenCompletesTheLoopbackHandshake(t *testing.T) {
	var authURL string
	open := func(u string) error {
		authURL = u
		parsed, err := url.Parse(u)
		if err != nil {
			return err
		}
		q := parsed.Query()
		go func() {
			if _, err := callback(q.Get("port"), q.Get("state"), "pat_minted_token"); err != nil {
				t.Errorf("callback request: %v", err)
			}
		}()
		return nil
	}

	var out strings.Builder
	token, err := requestToken("https://treehouse.test", "workshop-laptop", testInstanceID, &out, open)
	if err != nil {
		t.Fatalf("requestToken: %v", err)
	}
	if token != "pat_minted_token" {
		t.Fatalf("expected the minted token back, got %q", token)
	}

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	if parsed.Path != "/auth/cli" {
		t.Fatalf("expected the approval page, got %q", parsed.Path)
	}
	// The approval page names the machine being connected and keys the token
	// it mints to it, so a login that omits it cannot be approved meaningfully.
	if got := parsed.Query().Get("machine"); got != "workshop-laptop" {
		t.Fatalf("expected the machine name in the auth url, got %q", got)
	}
	if parsed.Query().Get("state") == "" {
		t.Fatal("expected a state parameter in the auth url")
	}

	// The approval URL must also reach the terminal, so a user whose browser
	// silently failed to open (SSH, container, no default browser) can still
	// copy it.
	if !strings.Contains(out.String(), authURL) {
		t.Fatalf("expected the approval URL printed for copy-paste, got %q", out.String())
	}
}

// A machine name is what the approval prompt shows the user. Opening the
// browser without one produces a prompt that cannot say what is being
// connected, so the flow refuses before it starts rather than asking someone
// to approve an unnamed machine.
func TestRequestTokenRequiresAMachineName(t *testing.T) {
	opened := false
	open := func(string) error {
		opened = true
		return nil
	}
	if _, err := requestToken("https://treehouse.test", "   ", testInstanceID, io.Discard, open); err == nil {
		t.Fatal("expected a login with no machine name to fail")
	}
	if opened {
		t.Fatal("the browser must not be opened for a login that cannot be approved")
	}
}

// Any local process can reach the loopback port. A stray or malformed request
// gets rejected, but must not resolve the pending login -- doing so would let
// one bad request deny the user the login it is interfering with.
func TestRequestTokenSurvivesRequestsThatAreNotTheRealCallback(t *testing.T) {
	open := func(u string) error {
		parsed, err := url.Parse(u)
		if err != nil {
			return err
		}
		q := parsed.Query()
		port, state := q.Get("port"), q.Get("state")
		go func() {
			// Wrong state, then a missing token, then the genuine callback.
			if status, err := callback(port, "not-the-state", "pat_attacker"); err != nil || status != http.StatusBadRequest {
				t.Errorf("expected a state mismatch to be rejected, got status %d err %v", status, err)
			}
			if status, err := callback(port, state, ""); err != nil || status != http.StatusBadRequest {
				t.Errorf("expected a missing token to be rejected, got status %d err %v", status, err)
			}
			if _, err := callback(port, state, "pat_real_token"); err != nil {
				t.Errorf("genuine callback request: %v", err)
			}
		}()
		return nil
	}

	done := make(chan struct{})
	var token string
	var err error
	go func() {
		token, err = requestToken("https://treehouse.test", "laptop", testInstanceID, io.Discard, open)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("login did not complete after the rejected requests")
	}
	if err != nil {
		t.Fatalf("requestToken: %v", err)
	}
	if token != "pat_real_token" {
		t.Fatalf("expected the genuine callback's token, got %q", token)
	}
}

func TestRequestTokenFailsWhenTheBrowserCannotOpen(t *testing.T) {
	_, err := requestToken("https://treehouse.test", "laptop", testInstanceID, io.Discard, func(string) error {
		return fmt.Errorf("no browser here")
	})
	if err == nil {
		t.Fatal("expected a browser launch failure to fail the login")
	}
	if !strings.Contains(err.Error(), "no browser here") {
		t.Fatalf("expected the underlying failure to be reported, got %v", err)
	}
}

// An empty web URL means the caller's own config resolution failed. Defaulting
// to production there would point a misconfigured dev daemon at the real
// account and mint a real token against it.
func TestRequestTokenRefusesAnUnconfiguredWebURL(t *testing.T) {
	opened := false
	_, err := requestToken("", "laptop", testInstanceID, io.Discard, func(string) error {
		opened = true
		return nil
	})
	if err == nil {
		t.Fatal("expected an unconfigured web URL to fail")
	}
	if opened {
		t.Fatal("the browser must not be opened without a configured web URL")
	}
}
