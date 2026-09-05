package auth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// The device authorization flow (RFC 8628), for a machine with no reachable
// browser.
//
// The loopback login in oauth.go cannot work here: approval redirects to a
// listener on this process's own 127.0.0.1, so a browser on any other device
// resolves that to itself and reaches nothing. Here nothing has to reach this
// machine at all -- it starts the flow, prints a short code, and polls until a
// signed-in human approves it from whatever device they are holding.

const (
	// defaultPollInterval is used only if the server does not say. The server
	// enforces its own interval and answers slow_down, so this is a fallback,
	// not the authority.
	defaultPollInterval = 5 * time.Second

	// slowDownStep is what a slow_down answer adds to the interval, per
	// RFC 8628: back off rather than fail, because a person is standing there
	// waiting for this to finish.
	slowDownStep = 5 * time.Second

	// defaultCodeLifetime is used only if the server does not say how long its
	// code lives.
	defaultCodeLifetime = 10 * time.Minute

	// pollGracePeriod keeps polling a little past the server's own expiry, so
	// a daemon whose clock is slightly behind still gets the server's answer
	// rather than inventing a different error for the same situation.
	pollGracePeriod = time.Minute

	// deviceSealInfo domain-separates the credential envelope's key. Must match
	// the server's expected info string or nothing opens.
	deviceSealInfo = "th/device/v1"
)

// DeviceAuthorization is what the server hands back when a flow starts.
// DeviceCode is this machine's bearer secret for the flow and is never
// displayed; UserCode is what a human reads off the terminal.
type DeviceAuthorization struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
	ExpiresIn  int    `json:"expires_in"`
	Interval   int    `json:"interval"`

	// key is this flow's ephemeral private half. Its public half went up with
	// the request, and the credential comes back sealed to it, so nothing that
	// reads the server's store can use what it finds there. Never transmitted,
	// never written to disk -- it lives only as long as the command does.
	key *ecdh.PrivateKey
}

// sealedToken is the credential envelope returned by the server.
type sealedToken struct {
	EphemeralPublic string `json:"ephPub"`
	Nonce           string `json:"nonce"`
	Ciphertext      string `json:"ct"`
}

type devicePollResponse struct {
	Status      string `json:"status"`
	AccessToken string `json:"access_token"`
	ApprovedBy  string `json:"approved_by"`
}

// ErrDeviceAuthorizationExpired means nobody approved in time. Distinct from a
// transport failure: the answer is to run the command again, not to retry.
var ErrDeviceAuthorizationExpired = errors.New("device authorization expired before it was approved")

// StartDeviceAuthorization asks the server for a code pair.
//
// machineInstanceID must already exist, because the credential this flow
// eventually returns is bound to it at mint time -- the same ordering
// constraint the browser login has.
func StartDeviceAuthorization(apiGatewayURL, machineName, machineInstanceID string) (*DeviceAuthorization, error) {
	// Generated per flow and kept in memory. The credential comes back sealed
	// to this key, which is what keeps a usable token from ever sitting in the
	// server's store in the clear.
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate device key: %w", err)
	}

	body, err := json.Marshal(map[string]string{
		"machine_instance_id": machineInstanceID,
		"machine_name":        machineName,
		"public_key":          base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
	})
	if err != nil {
		return nil, fmt.Errorf("encode device request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, apiGatewayURL+"/v1/treehouse/device/start", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build device request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("start device authorization: %w", err)
	}
	defer resp.Body.Close()

	payload, readErr := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("start device authorization failed (%d): %s", resp.StatusCode, errorMessage(payload))
	}
	if readErr != nil {
		return nil, fmt.Errorf("read device response: %w", readErr)
	}

	var authorization DeviceAuthorization
	if err := json.Unmarshal(payload, &authorization); err != nil {
		return nil, fmt.Errorf("decode device response: %w", err)
	}
	if authorization.DeviceCode == "" || authorization.UserCode == "" {
		return nil, fmt.Errorf("device authorization response is missing its codes")
	}
	authorization.key = key
	return &authorization, nil
}

// PollDeviceAuthorization waits for a human to approve, and returns the
// credential once one does.
//
// ctx is what makes Ctrl-C work while waiting, which matters because this
// command's normal state is waiting.
func PollDeviceAuthorization(ctx context.Context, apiGatewayURL string, authorization *DeviceAuthorization) (token, approvedBy string, err error) {
	interval := time.Duration(authorization.Interval) * time.Second
	if interval <= 0 {
		interval = defaultPollInterval
	}
	// The server's own expiry, plus a grace period, rather than a constant:
	// changing the code's lifetime server-side should move this with it, and
	// outlasting it by a little means the daemon reports the server's
	// "expired" rather than inventing its own for the same situation.
	lifetime := time.Duration(authorization.ExpiresIn) * time.Second
	if lifetime <= 0 {
		lifetime = defaultCodeLifetime
	}
	deadline := time.Now().Add(lifetime + pollGracePeriod)
	client := &http.Client{Timeout: 30 * time.Second}

	for {
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(interval):
		}
		if time.Now().After(deadline) {
			return "", "", ErrDeviceAuthorizationExpired
		}

		sealed, approver, status, err := pollOnce(ctx, client, apiGatewayURL, authorization.DeviceCode)
		if err != nil {
			if errors.Is(err, ErrDeviceAuthorizationExpired) {
				return "", "", err
			}
			// A dropped connection during a ten-minute wait must not end the
			// flow -- the person is standing at a terminal and the code is
			// still good. Keep polling until the deadline says otherwise.
			continue
		}
		switch status {
		case "approved":
			opened, err := authorization.open(sealed)
			if err != nil {
				return "", "", err
			}
			return opened, approver, nil
		case "slow_down":
			// Back off rather than fail: polling too fast is this client's
			// bug, and failing the login would punish the person waiting.
			interval += slowDownStep
		case "pending":
			// The normal answer to almost every poll.
		default:
			return "", "", fmt.Errorf("unexpected device authorization status %q", status)
		}
	}
}

// open unwraps the credential sealed to this flow's ephemeral key.
func (a *DeviceAuthorization) open(envelope string) (string, error) {
	if a.key == nil {
		return "", fmt.Errorf("device authorization has no key to open its credential with")
	}
	var sealed sealedToken
	if err := json.Unmarshal([]byte(envelope), &sealed); err != nil {
		return "", fmt.Errorf("decode credential envelope: %w", err)
	}
	ephBytes, err := base64.RawURLEncoding.DecodeString(sealed.EphemeralPublic)
	if err != nil {
		return "", fmt.Errorf("decode credential envelope key: %w", err)
	}
	ephPub, err := ecdh.P256().NewPublicKey(ephBytes)
	if err != nil {
		return "", fmt.Errorf("credential envelope key is not a valid P-256 point: %w", err)
	}
	shared, err := a.key.ECDH(ephPub)
	if err != nil {
		return "", fmt.Errorf("ecdh: %w", err)
	}
	key, err := hkdf.Key(sha256.New, shared, nil, deviceSealInfo, 32)
	if err != nil {
		return "", fmt.Errorf("derive credential key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(sealed.Nonce)
	if err != nil {
		return "", fmt.Errorf("decode credential nonce: %w", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(sealed.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("decode credential ciphertext: %w", err)
	}
	token, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("the credential was not sealed for this machine: %w", err)
	}
	return string(token), nil
}

func pollOnce(ctx context.Context, client *http.Client, apiGatewayURL, deviceCode string) (sealed, approvedBy, status string, err error) {
	body, err := json.Marshal(map[string]string{"device_code": deviceCode})
	if err != nil {
		return "", "", "", fmt.Errorf("encode device poll: %w", err)
	}
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, apiGatewayURL+"/v1/treehouse/device/token", bytes.NewReader(body))
	if err != nil {
		return "", "", "", fmt.Errorf("build device poll: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("poll device authorization: %w", err)
	}
	defer resp.Body.Close()

	payload, readErr := io.ReadAll(resp.Body)
	// A code the server no longer knows is expired, collected, or was never
	// real. All three mean the same thing to someone standing at a terminal:
	// start again.
	if resp.StatusCode == http.StatusNotFound {
		return "", "", "", ErrDeviceAuthorizationExpired
	}
	if resp.StatusCode >= 400 {
		return "", "", "", fmt.Errorf("poll device authorization failed (%d): %s", resp.StatusCode, errorMessage(payload))
	}
	if readErr != nil {
		return "", "", "", fmt.Errorf("read device poll response: %w", readErr)
	}

	var parsed devicePollResponse
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return "", "", "", fmt.Errorf("decode device poll response: %w", err)
	}
	return parsed.AccessToken, parsed.ApprovedBy, parsed.Status, nil
}

// errorBodyTruncateLen bounds what an unexpected error body contributes to a
// message someone reads in a terminal.
const errorBodyTruncateLen = 200

// errorMessage turns a server error body into a short line rather than
// dumping raw JSON at someone trying to connect a machine. Server errors are
// always {"error": "..."}; anything else (a proxy's HTML page, an empty body)
// falls back to a truncated body rather than losing it entirely.
//
// A deliberate twin of ingest.errorMessage. Sharing it would make this
// package depend on the ingest package purely for a dozen lines of string
// handling, and auth sits below ingest, not beside it.
func errorMessage(body []byte) string {
	var parsed struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil && parsed.Error != "" {
		return parsed.Error
	}
	s := string(body)
	if len(s) > errorBodyTruncateLen {
		return s[:errorBodyTruncateLen] + "…"
	}
	return s
}
