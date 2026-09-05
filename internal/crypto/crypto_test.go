package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/zalando/go-keyring"
)

type memoryStore struct {
	value   string
	sets    int
	deletes int
	getErr  error
	setErr  error
}

func (m *memoryStore) Get() (string, error) { return m.value, m.getErr }
func (m *memoryStore) Set(v string) error {
	if m.setErr != nil {
		return m.setErr
	}
	m.value = v
	m.sets++
	return nil
}
func (m *memoryStore) Delete() error { m.value = ""; m.deletes++; return nil }

// testIdentity is a stored record with valid, distinguishable fields, used to
// exercise decoding without generating one.
func storedRecord(id string) string {
	return `{"id":"` + id + `","mck":"` +
		b64.EncodeToString(make([]byte, keyLen)) + `","mtk":"` +
		b64.EncodeToString(make([]byte, keyLen)) + `","epoch":1}`
}

func TestEnsureGeneratesOnceAndIsStableAfterwards(t *testing.T) {
	store := &memoryStore{}

	first, err := EnsureIn(store, "")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := EnsureIn(store, "")
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	if string(first.MCK) != string(second.MCK) || string(first.MTK) != string(second.MTK) {
		t.Fatal("keys must be stable across calls; a machine that re-keys silently orphans every grant it has issued")
	}
	if first.InstanceID != second.InstanceID {
		t.Fatal("identity must be stable: a machine that changes it becomes a new machine, orphaning its grants")
	}
	if first.InstanceID == uuid.Nil {
		t.Fatal("expected a generated instance id")
	}
	if store.sets != 1 {
		t.Fatalf("expected one write, got %d", store.sets)
	}
	if len(first.MCK) != keyLen || len(first.MTK) != keyLen {
		t.Fatalf("expected %d-byte keys, got %d and %d", keyLen, len(first.MCK), len(first.MTK))
	}
	if string(first.MCK) == string(first.MTK) {
		t.Fatal("the token key must be independent of the content key, or a future rotation would change every content fingerprint at once")
	}
}

// Replacing unreadable keys would leave every already-issued grant unopenable,
// with readers seeing decryption failures and nothing saying why.
func TestEnsureRefusesUnreadableStoredKeys(t *testing.T) {
	for name, stored := range map[string]string{
		"not json":       "{{{",
		"short key":      `{"id":"66666666-6666-6666-6666-666666666666","mck":"AAAA","mtk":"AAAA","epoch":1}`,
		"empty":          `{"id":"66666666-6666-6666-6666-666666666666","mck":"","mtk":"","epoch":1}`,
		"bad base64":     `{"id":"66666666-6666-6666-6666-666666666666","mck":"!!!!","mtk":"!!!!","epoch":1}`,
		"no instance id": `{"mck":"` + b64.EncodeToString(make([]byte, keyLen)) + `","mtk":"` + b64.EncodeToString(make([]byte, keyLen)) + `","epoch":1}`,
		"bad instance id": `{"id":"not-a-uuid","mck":"` + b64.EncodeToString(make([]byte, keyLen)) +
			`","mtk":"` + b64.EncodeToString(make([]byte, keyLen)) + `","epoch":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			store := &memoryStore{value: stored}
			_, err := EnsureIn(store, "")
			if err == nil {
				t.Fatal("expected a refusal rather than a silent regeneration")
			}
			// The message has to name a recovery that actually works. `logout`
			// alone deletes the token and leaves this record exactly as it was.
			if !strings.Contains(err.Error(), "--reset-machine") {
				t.Fatalf("the error should name the recovery, got %q", err)
			}
			if store.sets != 0 {
				t.Fatal("must not overwrite a record it could not read")
			}
		})
	}
}

// The whole reason identity and keys share one record: split across two, a
// keychain that loses only the keys leaves this host claiming its old identity
// while sealing under a new content key. Every grant the server has already
// filled is immutable, so it stays wrapped to the dead key and the
// reader decrypts nothing, forever, with no error explaining it.
func TestIdentityAndKeysAreLostTogether(t *testing.T) {
	store := &memoryStore{}
	first, err := EnsureIn(store, "")
	if err != nil {
		t.Fatalf("first: %v", err)
	}

	if err := ResetIn(store); err != nil {
		t.Fatalf("reset: %v", err)
	}
	second, err := EnsureIn(store, "")
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	if second.InstanceID == first.InstanceID {
		t.Fatal("new keys must come with a new instance id, or already-filled grants wrap a key nothing can use")
	}
	if string(second.MCK) == string(first.MCK) {
		t.Fatal("a reset must produce new key material")
	}
}

// Two machines must never share an identity, or one machine's grants unwrap
// the other's diffs.
func TestEnsureGeneratesDistinctIdentitiesForDistinctMachines(t *testing.T) {
	a, err := EnsureIn(&memoryStore{}, "")
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := EnsureIn(&memoryStore{}, "")
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a.InstanceID == b.InstanceID {
		t.Fatal("two machines must not share an instance id")
	}
}

func TestEnsureUsesTheEnvironmentOverride(t *testing.T) {
	const override = "88888888-8888-4888-8888-888888888888"
	store := &memoryStore{}

	got, err := EnsureIn(store, "  "+storedRecord(override)+"  ")
	if err != nil {
		t.Fatalf("override: %v", err)
	}
	if got.InstanceID.String() != override {
		t.Fatalf("expected %s, got %s", override, got.InstanceID)
	}
	if store.sets != 0 {
		t.Fatal("an override must not be persisted over the stored record")
	}
}

func TestEnsurePropagatesStoreFailures(t *testing.T) {
	readFailure := errors.New("keychain locked")
	if _, err := EnsureIn(&memoryStore{getErr: readFailure}, ""); !errors.Is(err, readFailure) {
		t.Fatalf("a keychain that cannot be read must not look like a fresh machine, got %v", err)
	}

	writeFailure := errors.New("keychain read-only")
	if _, err := EnsureIn(&memoryStore{setErr: writeFailure}, ""); err == nil {
		t.Fatal("an identity that could not be stored must not be returned as if it had been")
	}
}

// The wrap has to be openable by a reader that only ever sees the envelope, so
// this test plays the reader: it derives the same KEK from its own private key
// and the ephemeral public key in the envelope, exactly as WebCrypto would.
func TestWrapMachineKeyIsOpenableByTheIntendedReader(t *testing.T) {
	keys, err := EnsureIn(&memoryStore{}, "")
	if err != nil {
		t.Fatalf("keys: %v", err)
	}

	readerPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("reader key: %v", err)
	}
	readerPub := b64.EncodeToString(readerPriv.PublicKey().Bytes())

	const readerKeyID = "77777777-7777-7777-7777-777777777777"
	instanceID := keys.InstanceID.String()

	raw, err := WrapMachineKey(keys, readerKeyID, readerPub)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	var envelope WrappedMachineKey
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		t.Fatalf("envelope is not JSON: %v", err)
	}
	if envelope.Version != envelopeVersion || envelope.Epoch != keys.Epoch {
		t.Fatalf("unexpected envelope header: %+v", envelope)
	}
	if envelope.MachineInstanceID != instanceID || envelope.ReaderKeyID != readerKeyID {
		t.Fatalf("envelope must be self-describing: %+v", envelope)
	}

	opened := openAsReader(t, readerPriv, envelope)
	if string(opened) != string(keys.MCK) {
		t.Fatal("the reader must recover exactly the machine content key")
	}
}

// A grant is bound to the machine and epoch it names, so an envelope replayed
// under a different identity must fail rather than decrypt to something.
func TestWrapIsBoundToItsMachineAndEpoch(t *testing.T) {
	keys, _ := EnsureIn(&memoryStore{}, "")
	readerPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	readerPub := b64.EncodeToString(readerPriv.PublicKey().Bytes())

	raw, err := WrapMachineKey(keys, "reader", readerPub)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	var envelope WrappedMachineKey
	_ = json.Unmarshal([]byte(raw), &envelope)

	// Same bytes, different claimed machine: the KEK no longer derives.
	envelope.MachineInstanceID = "99999999-9999-9999-9999-999999999999"
	if _, err := tryOpenAsReader(readerPriv, envelope); err == nil {
		t.Fatal("an envelope replayed under another machine's identity must not open")
	}

	envelope.MachineInstanceID = keys.InstanceID.String()
	envelope.Epoch = keys.Epoch + 1
	if _, err := tryOpenAsReader(readerPriv, envelope); err == nil {
		t.Fatal("an envelope replayed under another epoch must not open")
	}
}

func TestWrapRejectsAKeyThatIsNotAPoint(t *testing.T) {
	keys, _ := EnsureIn(&memoryStore{}, "")
	for name, key := range map[string]string{
		"not base64":   "!!!!",
		"wrong length": b64.EncodeToString([]byte("too short")),
		"off curve":    b64.EncodeToString(make([]byte, 65)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := WrapMachineKey(keys, "reader", key); err == nil {
				t.Fatal("expected a rejection")
			}
		})
	}
}

// openAsReader mirrors what the web client reader does in WebCrypto: ECDH against the
// envelope's ephemeral public key, HKDF with the same info string, AES-GCM.
func openAsReader(t *testing.T, priv *ecdh.PrivateKey, envelope WrappedMachineKey) []byte {
	t.Helper()
	plaintext, err := tryOpenAsReader(priv, envelope)
	if err != nil {
		t.Fatalf("reader could not open the grant: %v", err)
	}
	return plaintext
}

func tryOpenAsReader(priv *ecdh.PrivateKey, envelope WrappedMachineKey) ([]byte, error) {
	ephBytes, err := b64.DecodeString(envelope.EphemeralPublic)
	if err != nil {
		return nil, err
	}
	ephPub, err := ecdh.P256().NewPublicKey(ephBytes)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, err
	}

	info := append([]byte(grantInfoPrefix), lengthPrefixed(envelope.MachineInstanceID)...)
	var epochBytes [4]byte
	binary.BigEndian.PutUint32(epochBytes[:], envelope.Epoch)
	info = append(info, epochBytes[:]...)

	kek, err := hkdf.Key(sha256.New, shared, nil, string(info), keyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := b64.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := b64.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Length prefixing exists so two different field lists cannot produce the same
// derivation input. Without it "ab"+"c" and "a"+"bc" are one string.
func TestLengthPrefixingSeparatesFields(t *testing.T) {
	if string(lengthPrefixed("ab", "c")) == string(lengthPrefixed("a", "bc")) {
		t.Fatal("different field lists must not produce identical derivation input")
	}
}

func TestEnvironmentOverrideWins(t *testing.T) {
	store := &memoryStore{}
	seeded, err := EnsureIn(store, "")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	override, err := EnsureIn(&memoryStore{}, store.value)
	if err != nil {
		t.Fatalf("override: %v", err)
	}
	if string(override.MCK) != string(seeded.MCK) {
		t.Fatal("the override must be used verbatim")
	}
	if !strings.Contains(store.value, `"mck"`) {
		t.Fatal("stored form should be the documented JSON shape")
	}
}

// fakeKeyring stands in for the OS keychain.
//
// Every test below uses one. An earlier version of this file called
// KeyringStore() directly, which on a developer's machine writes to and
// deletes from the real keychain -- running the suite destroyed the machine
// identity of whoever ran it. Tests do not get to touch that.
type fakeKeyring struct {
	values    map[string]string
	getErr    error
	setErr    error
	deleteErr error
	// unavailable models a host with no Secret Service at all: every read
	// fails, including the availability probe.
	unavailable bool
}

func newFakeKeyring() *fakeKeyring { return &fakeKeyring{values: map[string]string{}} }

func (f *fakeKeyring) Get(service, user string) (string, error) {
	if f.unavailable {
		return "", errors.New("dbus: couldn't determine address of session bus")
	}
	if f.getErr != nil && user == keyringUser {
		return "", f.getErr
	}
	value, ok := f.values[user]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return value, nil
}

func (f *fakeKeyring) Set(service, user, value string) error {
	if f.unavailable || f.setErr != nil {
		if f.setErr != nil {
			return f.setErr
		}
		return errors.New("no keychain")
	}
	f.values[user] = value
	return nil
}

func (f *fakeKeyring) Delete(service, user string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if _, ok := f.values[user]; !ok {
		return keyring.ErrNotFound
	}
	delete(f.values, user)
	return nil
}

// A headless Linux server usually has no D-Bus session and so no Secret
// Service. Without a fallback, the keychain read fails and `treehouse pair` --
// the command that exists for exactly those machines -- cannot generate the
// identity it needs to start.
func TestIdentityFallsBackToAFileWhenThereIsNoKeychain(t *testing.T) {
	t.Setenv(EnvIdentityPath, filepath.Join(t.TempDir(), "nested", "machine-identity.json"))
	store := keyringStore{backend: &fakeKeyring{unavailable: true}, noKeychain: func(error) bool { return true }}

	first, err := EnsureIn(store, "")
	if err != nil {
		t.Fatalf("a host with no keychain must still be able to enroll: %v", err)
	}
	second, err := EnsureIn(store, "")
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	if first.InstanceID != second.InstanceID {
		t.Fatal("the file fallback must return the same identity, not mint a new one each time")
	}
}

// The failure that matters most, because its damage is silent and delayed. A
// keychain that is merely locked -- a denied prompt, a transient permissions
// problem -- must never read as a first run: generating a second identity
// beside the real one breaks the token binding and orphans every grant the
// moment the keychain comes back.
func TestALockedKeychainFailsClosedRatherThanMintingANewIdentity(t *testing.T) {
	t.Setenv(EnvIdentityPath, filepath.Join(t.TempDir(), "machine-identity.json"))
	backend := newFakeKeyring()
	backend.getErr = errors.New("keychain is locked")
	// A keychain that exists: locking a collection requires a bus to lock it
	// on, which is exactly why absence is decided from the environment rather
	// than from a second lookup that a locked collection fails identically.
	store := keyringStore{backend: backend, noKeychain: func(error) bool { return false }}

	if _, err := EnsureIn(store, ""); err == nil {
		t.Fatal("an ambiguous keychain read must fail rather than mint a second identity")
	}
	if _, err := os.Stat(os.Getenv(EnvIdentityPath)); !os.IsNotExist(err) {
		t.Fatal("a locked keychain must not cause a competing file identity to be written")
	}
}

// The keychain wins wherever one works: the file is a fallback, not a cache,
// and preferring it would strand a machine on a stale copy.
func TestAWorkingKeychainIsPreferredOverTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine-identity.json")
	t.Setenv(EnvIdentityPath, path)
	if err := writeIdentityFile(`{"id":"11111111-1111-4111-8111-111111111111","mck":"` +
		strings.Repeat("A", 43) + `","mtk":"` + strings.Repeat("B", 43) + `","epoch":1}`); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	backend := newFakeKeyring()
	backend.values[keyringUser] = `{"id":"22222222-2222-4222-8222-222222222222","mck":"` +
		strings.Repeat("C", 43) + `","mtk":"` + strings.Repeat("D", 43) + `","epoch":1}`

	identity, err := EnsureIn(keyringStore{backend: backend, noKeychain: func(error) bool { return false }}, "")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if identity.InstanceID.String() != "22222222-2222-4222-8222-222222222222" {
		t.Fatalf("the keychain copy must win, got %s", identity.InstanceID)
	}
}

// The file holds MCK and MTK. A copy other users can read is worth stopping on
// rather than quietly using, the same rule the credentials file already
// applies to the access token.
func TestIdentityFileMustNotBeWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine-identity.json")
	t.Setenv(EnvIdentityPath, path)
	if err := os.WriteFile(path, []byte(`{"id":"x"}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := readIdentityFile(); err == nil {
		t.Fatal("a group- or world-readable identity file must be refused")
	}
}

// Written at 0600 inside a 0700 directory, so the fallback is not a downgrade
// on a machine that has to use it.
func TestIdentityFileIsWrittenPrivately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "machine-identity.json")
	t.Setenv(EnvIdentityPath, path)

	if err := writeIdentityFile(`{"id":"x"}`); err != nil {
		t.Fatalf("write: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600, got %v", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("expected the directory to be 0700, got %v", dirInfo.Mode().Perm())
	}
}

// `treehouse logout --reset-machine` has to clear both, or the record comes
// back from whichever half was left behind.
func TestResetClearsBothTheKeychainAndTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine-identity.json")
	t.Setenv(EnvIdentityPath, path)
	backend := newFakeKeyring()
	backend.values[keyringUser] = `{"id":"x"}`
	if err := writeIdentityFile(`{"id":"x"}`); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := ResetIn(keyringStore{backend: backend, noKeychain: func(error) bool { return false }}); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, ok := backend.values[keyringUser]; ok {
		t.Fatal("the keychain copy must be gone after a reset")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the identity file must be gone after a reset")
	}
}

// A reset that could not clear the keychain must say so. Reporting success
// there leaves the old identity to reappear on the next run, which is exactly
// the confusion the reset was meant to end.
func TestResetReportsAKeychainFailureRatherThanSwallowingIt(t *testing.T) {
	t.Setenv(EnvIdentityPath, filepath.Join(t.TempDir(), "machine-identity.json"))
	backend := newFakeKeyring()
	backend.values[keyringUser] = `{"id":"x"}`
	backend.deleteErr = errors.New("keychain is locked")

	if err := ResetIn(keyringStore{backend: backend, noKeychain: func(error) bool { return false }}); err == nil {
		t.Fatal("a keychain deletion failure must be reported, not logged and hidden")
	}
}

// A host that stored its identity in the file and later gains a desktop
// session lands on an empty-but-working keychain. Declaring first run there
// mints a second identity and strands the token and every grant that were bound
// to the first.
func TestAnEmptyKeychainStillHonoursAnExistingFileIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine-identity.json")
	t.Setenv(EnvIdentityPath, path)
	stored := `{"id":"11111111-1111-4111-8111-111111111111","mck":"` + strings.Repeat("A", 43) +
		`","mtk":"` + strings.Repeat("B", 43) + `","epoch":1}`
	if err := writeIdentityFile(stored); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// The keychain works and simply has nothing -- ErrNotFound, not an error.
	store := keyringStore{backend: newFakeKeyring(), noKeychain: func(error) bool { return false }}

	identity, err := EnsureIn(store, "")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if identity.InstanceID.String() != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("the file identity must be kept, got %s", identity.InstanceID)
	}
}

// On a host with no keychain, `--reset-machine` has to succeed: the keychain
// deletion always fails there, and reporting it would mean the command mutates
// state and then returns an error on exactly the machines the file is for.
func TestResetSucceedsOnAHostWithNoKeychain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine-identity.json")
	t.Setenv(EnvIdentityPath, path)
	if err := writeIdentityFile(`{"id":"x"}`); err != nil {
		t.Fatalf("write: %v", err)
	}
	backend := newFakeKeyring()
	backend.deleteErr = errors.New("dbus: couldn't determine address of session bus")

	if err := ResetIn(keyringStore{backend: backend, noKeychain: func(error) bool { return true }}); err != nil {
		t.Fatalf("reset on a keychainless host must succeed: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the identity file must be gone")
	}
}

// The case the environment check alone could not see, and the one a real
// headless server actually hits: Debian and Ubuntu install dbus-user-session
// by default, so an SSH login has a live session bus with no secrets daemon
// behind it. Judging absence from the bus alone left `treehouse pair` failing
// on the most ordinary server there is.
func TestSecretServiceUnavailableRecognisesAHeadlessHost(t *testing.T) {
	absent := []string{
		"The name org.freedesktop.secrets was not provided by any .service files",
		"org.freedesktop.DBus.Error.Spawn.ChildExited",
		"dbus: couldn't determine address of session bus",
		"dial unix /run/user/1000/bus: connect: no such file or directory",
	}
	for _, message := range absent {
		if !secretServiceUnavailable(errors.New(message)) {
			t.Fatalf("expected %q to read as no Secret Service", message)
		}
	}
}

// The other half, and the more important one: a keychain that is present and
// declining must never read as absent. Minting a second identity beside the
// real one breaks the token binding and orphans every grant.
func TestSecretServiceUnavailableStillFailsClosedOnARefusal(t *testing.T) {
	present := []string{
		"prompt dismissed",
		"org.freedesktop.DBus.Error.NoReply: Message recipient disconnected",
		"dial unix /run/user/1000/bus: connect: permission denied",
		"The name org.freedesktop.secrets was not provided by any .service files",
	}
	for i, message := range present {
		// The last entry is the absent case, kept here so the two lists cannot
		// drift into agreeing with each other by accident.
		want := i == len(present)-1
		if got := secretServiceUnavailable(errors.New(message)); got != want {
			t.Fatalf("%q: expected %v, got %v", message, want, got)
		}
	}
	if secretServiceUnavailable(nil) {
		t.Fatal("no error is not evidence of an absent keychain")
	}
}

// End to end through the store, with the real classifier rather than the test
// stub: a host whose keychain reports no Secret Service must be able to
// enroll, and must come back with the same identity afterwards.
func TestAHostWithABusButNoSecretServiceCanStillEnroll(t *testing.T) {
	if runtime.GOOS != "linux" {
		// keychainAbsent only ever answers true on Linux, and deliberately so:
		// macOS and Windows always have a keychain. Exercised on Linux CI.
		t.Skip("Secret Service classification is Linux-only")
	}
	t.Setenv(EnvIdentityPath, filepath.Join(t.TempDir(), "machine-identity.json"))
	backend := newFakeKeyring()
	backend.getErr = errors.New(
		"The name org.freedesktop.secrets was not provided by any .service files")
	backend.setErr = backend.getErr
	store := keyringStore{backend: backend}

	first, err := EnsureIn(store, "")
	if err != nil {
		t.Fatalf("a host with a bus but no secrets daemon must still enroll: %v", err)
	}
	second, err := EnsureIn(store, "")
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	if first.InstanceID != second.InstanceID {
		t.Fatal("the file fallback must return the same identity, not mint a new one each time")
	}
}
