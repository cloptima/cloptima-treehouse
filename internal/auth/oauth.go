package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cloptima/cloptima-treehouse/internal/tray"
)

// The last screen of the browser half of the flow, so it has to look like the
// same product as the consent page it just came from: the app's neutral
// palette in both themes and the Treehouse mark.
const successHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Treehouse — machine connected</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #fafafa;
      --card: #ffffff;
      --border: #e5e5e5;
      --text: #171717;
      --muted: #737373;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #0a0a0a;
        --card: #171717;
        --border: #262626;
        --text: #f5f5f5;
        --muted: #a3a3a3;
      }
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      -webkit-font-smoothing: antialiased;
      background: var(--bg);
      color: var(--text);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      padding: 20px;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 24px;
      max-width: 360px;
      width: 100%;
      box-sizing: border-box;
    }
    .brand { display: flex; align-items: center; gap: 8px; margin-bottom: 20px; }
    .brand svg { width: 20px; height: 20px; color: var(--text); }
    .brand span { font-size: 14px; font-weight: 700; letter-spacing: -0.01em; }
    h1 {
      display: flex; align-items: center; gap: 8px;
      margin: 0 0 4px 0; font-size: 19px; font-weight: 700; letter-spacing: -0.01em;
    }
    .dot { width: 8px; height: 8px; border-radius: 50%; background: #22c55e; flex: 0 0 auto; }
    p { color: var(--muted); font-size: 12.5px; line-height: 1.45; margin: 0; }
  </style>
</head>
<body>
  <div class="card">
    <div class="brand">
      <svg viewBox="0 0 130 130" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <line x1="49" y1="30" x2="49" y2="98" stroke="currentColor" stroke-width="10" stroke-linecap="round"/>
        <line x1="49" y1="64" x2="82" y2="44" stroke="currentColor" stroke-width="10" stroke-linecap="round"/>
        <circle cx="49" cy="30" r="13" fill="currentColor"/>
        <circle cx="49" cy="98" r="13" fill="currentColor"/>
        <circle cx="82" cy="44" r="13" fill="currentColor"/>
      </svg>
      <span>Treehouse</span>
    </div>
    <h1><span class="dot"></span>Machine connected</h1>
    <p>This machine is now reporting to your account. You can close this tab and go back to the menu bar app.</p>
  </div>
  <script>
    // Strip the token out of the address bar and this history entry as soon as
    // the page loads, so the long-lived credential does not linger in browser
    // history. The handshake is already complete by the time this runs.
    try { history.replaceState(null, '', '/callback'); } catch (e) {}
  </script>
</body>
</html>`

// Login initiates the 1-click browser OAuth flow:
//  1. Starts a temporary loopback HTTP server on 127.0.0.1:<free_port>
//  2. Generates a state token binding the callback to this listener
//  3. Opens the default browser to
//     ${webURL}/auth/cli?port=${port}&state=${state}&machine=${machineName}&instance=${machineInstanceID}
//  4. Awaits the callback redirect with the minted token
//  5. Stores the token securely in the OS keychain and returns it
//
// machineInstanceID is this machine's stable identity, and the page records
// it in the minted token's metadata so every later ingest can be checked
// against it. It is not a secret and the page cannot verify it either; the
// binding is what stops one member's token ingesting as another's machine,
// and the ownership check on the server is what makes the binding stick.
//
// machineName is not a security control -- the browser page cannot verify
// that whoever opened the link really is this machine, which is why that page
// requires an explicit human approval rather than minting on load. It is
// carried so the approval prompt can name the machine being connected, and so
// the minted token is identified by that machine and supersedes its previous
// token instead of accumulating one more per login.
//
// The approval URL is also written to out so the user can open it themselves
// when the OS opener exits cleanly without launching anything. It is only
// usable on this machine: the callback below is a listener on this process's
// own 127.0.0.1, so a browser on another device would redirect to its own
// loopback and reach nothing. Approving from elsewhere needs the device
// authorization flow, which is not this function.
func Login(webURL, machineName, machineInstanceID string, out io.Writer) (string, error) {
	token, err := requestToken(webURL, machineName, machineInstanceID, out, tray.OpenBrowser)
	if err != nil {
		return "", err
	}
	if _, err := SaveAccessTokenWithSource(token); err != nil {
		return "", fmt.Errorf("failed to save access token: %w", err)
	}
	return token, nil
}

// requestToken is Login without the keychain write, and takes the browser
// launcher as an argument so the whole loopback handshake can be driven in a
// test without opening a real browser or touching the real keychain.
func requestToken(webURL, machineName, machineInstanceID string, out io.Writer, openBrowser func(string) error) (string, error) {
	// No production default here. Every caller derives webURL from the
	// configured gateway (tray.ResolveWebURL), so an empty value means that
	// derivation failed -- and silently sending a misconfigured dev or staging
	// daemon to mint a real production token is the wrong way to fail.
	if strings.TrimSpace(webURL) == "" {
		return "", fmt.Errorf("no Treehouse web URL configured for browser login")
	}
	if strings.TrimSpace(machineName) == "" {
		return "", fmt.Errorf("machine name is required for browser login")
	}
	// The minted token is bound to this identity and every later ingest is
	// checked against it, so a login without one produces a token that cannot
	// sync at all. Failing here beats discovering it on the first push.
	if strings.TrimSpace(machineInstanceID) == "" {
		return "", fmt.Errorf("machine instance id is required for browser login")
	}

	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return "", fmt.Errorf("failed to generate csrf state: %w", err)
	}
	state := hex.EncodeToString(stateBytes)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("failed to start local auth listener: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	type authResult struct {
		token string
		err   error
	}
	resultCh := make(chan authResult, 1)

	mux := http.NewServeMux()
	server := &http.Server{
		Handler: mux,
		// Without this, a connection that opens and then sends nothing holds
		// a server goroutine for the whole three-minute login window. The
		// listener is loopback-only and short-lived, but it is still a
		// listener every local process can reach.
		ReadHeaderTimeout: 10 * time.Second,
	}

	// A stray or malformed request must not end the login. Any local process
	// can reach this port, and rejecting the caller while also failing the
	// user's real, still-pending login turns one bad request into a denial of
	// service against the flow it is trying to complete. Only a well-formed
	// callback resolves the login, and only the first one does -- later sends
	// are dropped rather than blocking on the buffered channel.
	deliver := func(res authResult) {
		select {
		case resultCh <- res:
		default:
		}
	}

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		cbState := r.URL.Query().Get("state")
		if cbState != state {
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
			return
		}

		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "Missing access token parameter", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(successHTML))

		deliver(authResult{token: token})
	})

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			deliver(authResult{err: err})
		}
	}()

	authURL := fmt.Sprintf("%s/auth/cli?port=%d&state=%s&machine=%s&instance=%s",
		webURL, port, state, url.QueryEscape(machineName), url.QueryEscape(machineInstanceID))
	if out != nil {
		fmt.Fprintf(out, "If your browser did not open, visit this URL on this machine to continue:\n\n  %s\n\n", authURL)
	}
	if err := openBrowser(authURL); err != nil {
		_ = server.Close()
		return "", fmt.Errorf("failed to open browser: %w", err)
	}

	select {
	case res := <-resultCh:
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		if res.err != nil {
			return "", res.err
		}
		return res.token, nil
	case <-time.After(3 * time.Minute):
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		return "", fmt.Errorf("timed out after 3 minutes — try again")
	}
}
