// Package crypto owns this machine's identity, its content keys, and the
// wrapping of those keys for reader devices.
//
// All three live in one keychain record, and that is the whole point of the
// record rather than a convenience. Identity and keys are meaningless apart:
// a grant is MCK wrapped and filed under an instance id, and the server records
// each grant immutably once so it cannot be replaced later. Keep them in two
// records and losing only one produces a machine that still claims its old
// identity while sealing under a new key -- every already-filled grant then
// unwraps a key that opens nothing, permanently, with no error saying why.
// One record means they are lost together, which is the correct coupling:
// a machine that has lost its content key is a new machine and has to
// re-enroll anyway.
//
// The identity itself is a UUID generated here on first run. It is not a
// secret. An unregistered instance id has never left the machine that
// generated it, which is enough to make first-write-wins registration safe;
// after registration it is ownership, not secrecy, that protects the machine.
//
// Two secrets ride alongside it:
//
//   - MCK, the machine content key, from which every worktree's diff key is
//     derived. It is epoch-versioned so that rotation can be added later
//     without a format change.
//   - MTK, the machine token key, used only to fingerprint diff content. It is
//     separate from MCK and never rotates, because deriving it from MCK would
//     make every worktree's fingerprint change the moment the machine re-keyed
//     -- which the server reads as "everything changed at once" and turns into
//     a settle notification per repo for work nobody touched.
//
// A grant is MCK wrapped for one reader device: ephemeral-static ECDH to a
// key-encryption key, then AES-GCM. The daemon never learns who the readers
// are beyond the public keys the server hands it on the response to its own
// push, and it holds no reader private key, so a grant it produces is opaque
// to everything except the device it was wrapped for.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"
	"github.com/zalando/go-keyring"
)

const (
	keyringService = "treehouse-daemon"
	keyringUser    = "machine-identity"

	// EnvMachineIdentity overrides the stored record. Useful for tests, and
	// for running two daemons against one keychain during development. It
	// carries identity and keys together for the same reason the record does.
	EnvMachineIdentity = "TREEHOUSE_MACHINE_IDENTITY"

	// keyLen is 32 bytes for both secrets: AES-256 for the content key, and a
	// full SHA-256 block for the token key.
	keyLen = 32

	// nonceLen is AES-GCM's standard 96-bit nonce.
	nonceLen = 12

	// envelopeVersion is the wire format, not the key epoch. The two move
	// independently: a rotation bumps the epoch, a format change bumps this.
	envelopeVersion = 1

	// grantInfoPrefix domain-separates the grant KEK from every other key
	// derived from the same material.
	grantInfoPrefix = "th/grant/v1"
)

// b64 is base64url without padding, everywhere, in both directions. Picking
// one encoding and using it for every binary field is what keeps the Go and
// WebCrypto sides from disagreeing about a value neither can see.
var b64 = base64.RawURLEncoding

// Identity is this machine: who it says it is, and what it seals with.
type Identity struct {
	// InstanceID is the machine's identity everywhere -- the grant KEK binds
	// it, the access token is minted against it, and the server keys machines on it.
	// Name is only a display label.
	InstanceID uuid.UUID
	MCK        []byte
	MTK        []byte
	Epoch      uint32
}

// storedIdentity is the keychain representation.
type storedIdentity struct {
	InstanceID string `json:"id"`
	MCK        string `json:"mck"`
	MTK        string `json:"mtk"`
	Epoch      uint32 `json:"epoch"`
}

// Store reads, writes and clears the record, so the daemon can be tested
// without a real keychain.
type Store interface {
	Get() (string, error)
	Set(value string) error
	Delete() error
}

// EnvIdentityPath overrides where the file fallback lives.
const EnvIdentityPath = "TREEHOUSE_IDENTITY_PATH"

const (
	identityDirName  = ".treehouse"
	identityFileName = "machine-identity.json"
)

// keyringBackend is the OS keychain, behind an interface so tests can exercise
// the fallback and failure paths without touching the developer's real
// keychain -- which is not hypothetical: a test calling the production adapter
// deletes the machine identity of whoever runs it.
type keyringBackend interface {
	Get(service, user string) (string, error)
	Set(service, user, value string) error
	Delete(service, user string) error
}

type osKeyring struct{}

func (osKeyring) Get(service, user string) (string, error) { return keyring.Get(service, user) }
func (osKeyring) Set(service, user, v string) error        { return keyring.Set(service, user, v) }
func (osKeyring) Delete(service, user string) error        { return keyring.Delete(service, user) }

// keyringStore keeps the identity in the OS keychain, falling back to a 0600
// file when there is demonstrably no keychain to talk to.
//
// The fallback is not comfort: a headless Linux server usually has no D-Bus
// session and so no Secret Service, and without it `treehouse pair` -- the
// command that exists for those machines -- cannot generate the identity it
// needs to start. The access token has had this fallback since before
// encryption (internal/auth/token.go); the identity never grew one.
//
// It does hold MCK and MTK, so a working keychain always wins: the file is
// read only when the keychain has nothing, and written only when the keychain
// refuses.
type keyringStore struct {
	backend keyringBackend
	// noKeychain reports whether this host has no OS keychain at all, given
	// the error the keychain just returned. A field so tests can model a
	// headless Linux box from any platform; production leaves it nil and gets
	// the real check.
	noKeychain func(error) bool
}

func (k keyringStore) keychainAbsent(err error) bool {
	if k.noKeychain != nil {
		return k.noKeychain(err)
	}
	return keychainAbsent(err)
}

// Get returns the stored record, "" for a genuine first run, or an error when
// it cannot tell which.
//
// Telling those apart is the whole of this function. Treating an ambiguous read
// as a first run would let a momentarily locked keychain mint a brand new
// identity beside the real one -- and when the keychain came back the daemon
// would flip between them, breaking the token binding and orphaning every grant.
//
// Order: a keychain that answers wins; a keychain that answers "nothing" still
// has to check the file, because a host that stored its identity there before
// gaining a Secret Service must not be treated as new; and a keychain that
// cannot answer falls back only when the platform demonstrably has no keychain
// at all.
func (k keyringStore) Get() (string, error) {
	value, err := k.backend.Get(keyringService, keyringUser)
	if err == nil && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value), nil
	}

	if err == nil || errors.Is(err, keyring.ErrNotFound) {
		// The keychain answered, and the answer was "nothing here". That is
		// not proof of a first run: a headless host that stored its identity
		// in the file and later gained a desktop session lands exactly here,
		// and minting a new identity would strand its token and every grant.
		fileValue, fileErr := readIdentityFile()
		if fileErr != nil {
			return "", fileErr
		}
		return fileValue, nil
	}

	// The keychain could not answer. The file is still the first thing to try:
	// if this host has one, it is the identity in use.
	fileValue, fileErr := readIdentityFile()
	if fileErr != nil {
		return "", fileErr
	}
	if fileValue != "" {
		return fileValue, nil
	}

	// Nothing stored anywhere, and a keychain that would not answer. Falling
	// back here is only safe when there is demonstrably no keychain to be
	// locked out of -- see keychainAbsent, and note that repeating the lookup
	// cannot tell these apart: go-keyring unlocks the collection before every
	// search, so a locked collection fails every read identically.
	if k.keychainAbsent(err) {
		log.Printf("no OS keychain on this host; storing the machine identity in %s", describeIdentityPath())
		return "", nil
	}
	return "", fmt.Errorf(
		"read machine identity: %w (the keychain is present but would not answer; unlock it, or set %s to store the identity in a file instead)",
		err, EnvIdentityPath)
}

// keychainAbsent reports whether this host has no OS keychain at all, given
// the error the keychain just returned.
//
// Two independent signals, because on Linux either can be the whole story and
// neither subsumes the other:
//
//   - No session bus. The Secret Service is reached over it, so no bus means
//     no keychain -- a fact about the environment that a locked collection
//     cannot imitate, since locking something requires a bus to lock it on.
//   - A bus that says nothing is listening on org.freedesktop.secrets. This is
//     the common headless case and the environment cannot see it: Debian and
//     Ubuntu install dbus-user-session by default, so an SSH login has a live
//     /run/user/<uid>/bus and no secrets daemon behind it. Judging by the bus
//     alone left `treehouse pair` -- the command that exists for those hosts --
//     failing on the most ordinary server there is.
//
// macOS and Windows always have a keychain, so a failure there is always a
// real failure and never grounds for falling back.
//
// Repeating the lookup would not help: go-keyring unlocks the collection
// before every search, so a locked collection fails every read identically.
// The error text is what separates them, and only the phrasings that mean
// "nothing is there to answer" count -- a refusal, a timeout, or a dismissed
// prompt still fails closed.
func keychainAbsent(err error) bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if noSessionBus() {
		return true
	}
	return secretServiceUnavailable(err)
}

func noSessionBus() bool {
	if strings.TrimSpace(os.Getenv("DBUS_SESSION_BUS_ADDRESS")) != "" {
		return false
	}
	if _, err := os.Stat(fmt.Sprintf("/run/user/%d/bus", os.Getuid())); err == nil {
		return false
	}
	return true
}

// secretServiceUnavailable reports whether a keyring error means the Secret
// Service is not on the bus, as opposed to being there and declining.
//
// Matched on the message rather than on a dbus.Error name because that is what
// survives the trip: go-keyring returns the dbus error as-is, and its Error()
// yields the human message, not the error name -- so the name is unreachable
// without making an indirect dependency direct and splitting this file by
// build tag. These strings come from dbus-daemon itself and are the stable
// part of that interface.
//
// Deliberately narrow. Anything not listed here -- a denied prompt, a timeout,
// a permissions error -- keeps the fail-closed path, because minting a second
// identity beside a real one breaks the token binding and orphans every grant.
func secretServiceUnavailable(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	for _, marker := range []string{
		// org.freedesktop.DBus.Error.ServiceUnknown: no secrets daemon, and
		// none activatable. The headless default.
		"was not provided by any .service files",
		// The service is activatable but could not be started.
		"org.freedesktop.dbus.error.spawn",
		// dbus.SessionBus() could not connect at all. Usually caught by
		// noSessionBus above, but not when a stale DBUS_SESSION_BUS_ADDRESS
		// points at a socket that is gone.
		"couldn't determine address of session bus",
		"dial unix: no such file or directory",
		"dial unix: connection refused",
		"connect: no such file or directory",
		"connect: connection refused",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func (k keyringStore) Set(value string) error {
	if err := k.backend.Set(keyringService, keyringUser, value); err != nil {
		if fileErr := writeIdentityFile(value); fileErr != nil {
			return fmt.Errorf("store machine identity in keychain: %w; store in identity file: %w", err, fileErr)
		}
		log.Printf("warning: stored machine identity in the identity file after keychain write failed: %v", err)
		return nil
	}
	return nil
}

// Delete clears both.
//
// A keychain failure is reported rather than swallowed -- a reset that claimed
// success while leaving the keychain copy would have the old identity reappear
// on the next run. Except where there is no keychain: on those hosts the
// deletion always fails, and reporting it would make `--reset-machine` mutate
// state and then return an error on exactly the machines the file exists for.
func (k keyringStore) Delete() error {
	keyringErr := k.backend.Delete(keyringService, keyringUser)
	if errors.Is(keyringErr, keyring.ErrNotFound) || k.keychainAbsent(keyringErr) {
		keyringErr = nil
	}
	fileErr := deleteIdentityFile()

	switch {
	case keyringErr != nil && fileErr != nil:
		return fmt.Errorf("delete machine identity from keychain: %w; delete identity file: %w", keyringErr, fileErr)
	case keyringErr != nil:
		return fmt.Errorf("delete machine identity from keychain: %w", keyringErr)
	default:
		return fileErr
	}
}

// KeyringStore is the production store.
func KeyringStore() Store { return keyringStore{backend: osKeyring{}} }

func describeIdentityPath() string {
	path, err := identityFilePath()
	if err != nil || path == "" {
		return "the identity file"
	}
	return path
}

func identityFilePath() (string, error) {
	if path := strings.TrimSpace(os.Getenv(EnvIdentityPath)); path != "" {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", nil
	}
	return filepath.Join(home, identityDirName, identityFileName), nil
}

func readIdentityFile() (string, error) {
	path, err := identityFilePath()
	if err != nil || path == "" {
		return "", err
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("stat identity file: %w", err)
	}
	// Refused rather than read: this file holds the machine's content keys,
	// and a readable-by-others copy is worth stopping on rather than using.
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("identity file %s must not be readable by group or others", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read identity file: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func writeIdentityFile(value string) error {
	path, err := identityFilePath()
	if err != nil {
		return err
	}
	if path == "" {
		return errors.New("identity file path is unavailable; set HOME or " + EnvIdentityPath)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create identity directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		return fmt.Errorf("write identity file: %w", err)
	}
	return nil
}

func deleteIdentityFile() error {
	path, err := identityFilePath()
	if err != nil || path == "" {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete identity file: %w", err)
	}
	return nil
}

// EnsureIn returns this machine's identity, generating it on first call and
// returning that same record on every later one.
//
// It has to run before `treehouse login`, not after: the instance id is bound
// into the access token at mint time, and a token minted without one cannot ingest at
// all.
func EnsureIn(store Store, envValue string) (*Identity, error) {
	raw := strings.TrimSpace(envValue)
	if raw == "" {
		stored, err := store.Get()
		if err != nil {
			return nil, err
		}
		raw = stored
	}

	if raw != "" {
		identity, err := decodeIdentity(raw)
		if err != nil {
			// A record we cannot read is not something to route around
			// quietly. Replacing it would give this host a new identity and
			// new keys while the server still holds the old machine and its
			// filled grants -- ingests refused as another member's machine,
			// or readers failing to decrypt, with nothing on either side
			// saying why. Better to stop and name the recovery.
			return nil, fmt.Errorf(
				"stored machine identity is unusable (%w); run `treehouse logout --reset-machine` to re-enroll this host", err)
		}
		return identity, nil
	}

	identity := &Identity{InstanceID: uuid.New(), MCK: make([]byte, keyLen), MTK: make([]byte, keyLen), Epoch: 1}
	if _, err := rand.Read(identity.MCK); err != nil {
		return nil, fmt.Errorf("generate machine content key: %w", err)
	}
	if _, err := rand.Read(identity.MTK); err != nil {
		return nil, fmt.Errorf("generate machine token key: %w", err)
	}

	encoded, err := json.Marshal(storedIdentity{
		InstanceID: identity.InstanceID.String(),
		MCK:        b64.EncodeToString(identity.MCK),
		MTK:        b64.EncodeToString(identity.MTK),
		Epoch:      identity.Epoch,
	})
	if err != nil {
		return nil, fmt.Errorf("encode machine identity: %w", err)
	}
	if err := store.Set(string(encoded)); err != nil {
		return nil, err
	}
	return identity, nil
}

// ResetIn clears the record so the next run enrolls as a brand-new machine.
// This is the documented recovery for an unreadable record, and the only way
// out of one -- the token is a separate secret, so deleting it fixes nothing
// here.
func ResetIn(store Store) error { return store.Delete() }

func decodeIdentity(raw string) (*Identity, error) {
	var stored storedIdentity
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	instanceID, err := uuid.Parse(strings.TrimSpace(stored.InstanceID))
	if err != nil {
		return nil, fmt.Errorf("instance id is not a valid UUID: %w", err)
	}
	mck, err := b64.DecodeString(stored.MCK)
	if err != nil || len(mck) != keyLen {
		return nil, fmt.Errorf("content key is not %d bytes", keyLen)
	}
	mtk, err := b64.DecodeString(stored.MTK)
	if err != nil || len(mtk) != keyLen {
		return nil, fmt.Errorf("token key is not %d bytes", keyLen)
	}
	epoch := stored.Epoch
	if epoch == 0 {
		epoch = 1
	}
	return &Identity{InstanceID: instanceID, MCK: mck, MTK: mtk, Epoch: epoch}, nil
}

// WrappedMachineKey is the grant envelope, as the reader receives it. Every
// binary field is base64url unpadded, and every one is length-checked on the
// way in, because these values cross a language boundary and a wrong length is
// far easier to diagnose here than as a decryption failure later.
type WrappedMachineKey struct {
	Version           int    `json:"v"`
	MachineInstanceID string `json:"machineInstanceId"`
	Epoch             uint32 `json:"epoch"`
	ReaderKeyID       string `json:"readerKeyId"`
	EphemeralPublic   string `json:"ephPub"`
	Nonce             string `json:"nonce"`
	Ciphertext        string `json:"ct"`
}

// lengthPrefixed writes uint32be(len(s)) ‖ s. Concatenating variable-length
// fields without it lets two different field lists produce identical derivation
// input, which is a silent way to derive the same key for different things.
func lengthPrefixed(parts ...string) []byte {
	var out []byte
	for _, part := range parts {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		out = append(out, size[:]...)
		out = append(out, part...)
	}
	return out
}

// WrapMachineKey wraps MCK for one reader device.
//
// The instance id comes from the identity itself rather than from a
// parameter: it is a KEK input, so wrapping under one id and filing under
// another produces a grant that unwraps to nothing.
//
// readerPublicKey is a 65-byte uncompressed SEC1 P-256 point, base64url
// unpadded -- what WebCrypto's "raw" export produces and what
// ecdh.P256().NewPublicKey consumes.
func WrapMachineKey(identity *Identity, readerKeyID, readerPublicKey string) (string, error) {
	machineInstanceID := identity.InstanceID.String()
	pubBytes, err := b64.DecodeString(readerPublicKey)
	if err != nil {
		return "", fmt.Errorf("reader public key is not base64url: %w", err)
	}
	readerPub, err := ecdh.P256().NewPublicKey(pubBytes)
	if err != nil {
		return "", fmt.Errorf("reader public key is not a valid P-256 point: %w", err)
	}

	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate ephemeral key: %w", err)
	}
	shared, err := ephemeral.ECDH(readerPub)
	if err != nil {
		return "", fmt.Errorf("ecdh: %w", err)
	}

	// Empty salt, and the epoch in the info string, so a grant wrapped under
	// one epoch cannot be replayed as one from another.
	info := append([]byte(grantInfoPrefix), lengthPrefixed(machineInstanceID)...)
	var epochBytes [4]byte
	binary.BigEndian.PutUint32(epochBytes[:], identity.Epoch)
	info = append(info, epochBytes[:]...)

	kek, err := hkdf.Key(sha256.New, shared, nil, string(info), keyLen)
	if err != nil {
		return "", fmt.Errorf("derive key-encryption key: %w", err)
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return "", fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, identity.MCK, nil)

	envelope, err := json.Marshal(WrappedMachineKey{
		Version:           envelopeVersion,
		MachineInstanceID: machineInstanceID,
		Epoch:             identity.Epoch,
		ReaderKeyID:       readerKeyID,
		EphemeralPublic:   b64.EncodeToString(ephemeral.PublicKey().Bytes()),
		Nonce:             b64.EncodeToString(nonce),
		Ciphertext:        b64.EncodeToString(ciphertext),
	})
	if err != nil {
		return "", fmt.Errorf("encode grant envelope: %w", err)
	}
	return string(envelope), nil
}
