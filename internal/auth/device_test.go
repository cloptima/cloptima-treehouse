package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// sealAsServer simulates server-side credential sealing.
// The two sides derive the same key from the same inputs or the credential
// never opens, and that failure would surface as "pairing silently doesn't
// work" rather than as anything diagnosable -- so it is worth restating here
// rather than sharing helpers across test boundaries.
func sealAsServer(t *testing.T, daemonPublicKey, token string) string {
	t.Helper()
	pubBytes, err := base64.RawURLEncoding.DecodeString(daemonPublicKey)
	if err != nil {
		t.Fatalf("decode daemon key: %v", err)
	}
	daemonPub, err := ecdh.P256().NewPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("daemon point: %v", err)
	}
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ephemeral: %v", err)
	}
	shared, err := ephemeral.ECDH(daemonPub)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	key, err := hkdf.Key(sha256.New, shared, nil, deviceSealInfo, 32)
	if err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	envelope, err := json.Marshal(sealedToken{
		EphemeralPublic: base64.RawURLEncoding.EncodeToString(ephemeral.PublicKey().Bytes()),
		Nonce:           base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext:      base64.RawURLEncoding.EncodeToString(gcm.Seal(nil, nonce, []byte(token), nil)),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return string(envelope)
}

func testAuthorization(t *testing.T) (*DeviceAuthorization, string) {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return &DeviceAuthorization{key: key},
		base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
}

// The credential never sits in the server's store in a form the store's holder
// can use; this is the other half of that, and if the two sides disagree about
// the derivation nothing pairs.
func TestDaemonOpensWhatTheServerSeals(t *testing.T) {
	authorization, publicKey := testAuthorization(t)

	opened, err := authorization.open(sealAsServer(t, publicKey, "pat_live_value"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if opened != "pat_live_value" {
		t.Fatalf("expected the minted credential, got %q", opened)
	}
}

// A credential sealed for a different machine must fail loudly rather than
// producing bytes that get saved as a token and then fail every push.
func TestCredentialSealedForAnotherMachineDoesNotOpen(t *testing.T) {
	authorization, _ := testAuthorization(t)
	_, otherPublicKey := testAuthorization(t)

	if _, err := authorization.open(sealAsServer(t, otherPublicKey, "pat_live_value")); err == nil {
		t.Fatal("a credential sealed for another machine must not open")
	}
}

// Every field crosses a language boundary, so a malformed envelope is worth a
// named error rather than a panic or a silently empty token.
func TestMalformedCredentialEnvelopesAreRejected(t *testing.T) {
	authorization, publicKey := testAuthorization(t)
	valid := sealAsServer(t, publicKey, "pat_live_value")

	for name, envelope := range map[string]string{
		"not json":            "{{{",
		"empty":               "{}",
		"ephemeral not a key": strings.Replace(valid, `"ephPub":"`, `"ephPub":"AAAA`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := authorization.open(envelope); err == nil {
				t.Fatal("expected a rejection")
			}
		})
	}

	// And an authorization that never started a flow has nothing to open with.
	empty := &DeviceAuthorization{}
	if _, err := empty.open(valid); err == nil {
		t.Fatal("an authorization with no key must not claim to open anything")
	}
}

// API Gateway serves the device flow under /v1/treehouse/daemon; the API
// contract owns the rest of /v1/treehouse, so the old paths answer 404.
func TestDeviceFlowCallsTheDaemonRoutes(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/treehouse/daemon/device/start":
			_, _ = w.Write([]byte(`{"device_code":"dc","user_code":"CDFG-HJKM","expires_in":600,"interval":1}`))
		case "/v1/treehouse/daemon/device/token":
			_, _ = w.Write([]byte(`{"status":"pending"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	authorization, err := StartDeviceAuthorization(server.URL, "build-box", "11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	_, _, status, err := pollOnce(context.Background(), server.Client(), server.URL, authorization.DeviceCode)
	if err != nil || status != "pending" {
		t.Fatalf("poll = %q, %v; want pending", status, err)
	}

	want := []string{"POST /v1/treehouse/daemon/device/start", "POST /v1/treehouse/daemon/device/token"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("called %v, want %v", paths, want)
	}
}
