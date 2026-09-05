package crypto

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"testing"
)

// openDiffAsReader is what the web client reader has to do: derive the
// worktree key from MCK and the two paths, AES-GCM decrypt with the epoch as
// additional data, then gunzip. Written out longhand rather than calling the
// production helpers, so a mistake in derivation shows up as a test failure
// here instead of agreeing with itself.
func openDiffAsReader(t *testing.T, mck []byte, epoch uint32, repoPath, wtPath string, sealed *SealedDiff) []byte {
	t.Helper()

	var salt [4]byte
	binary.BigEndian.PutUint32(salt[:], epoch)
	info := append([]byte(diffInfoPrefix), lengthPrefixed(repoPath, wtPath)...)
	key, err := hkdf.Key(sha256.New, mck, salt[:], string(info), keyLen)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	plaintext, err := openWithKey(key, epoch, sealed)
	if err != nil {
		t.Fatalf("reader could not open the sealed diff: %v", err)
	}
	return plaintext
}

func openWithKey(key []byte, epoch uint32, sealed *SealedDiff) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := b64.DecodeString(sealed.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := b64.DecodeString(sealed.Ciphertext)
	if err != nil {
		return nil, err
	}
	var aad [4]byte
	binary.BigEndian.PutUint32(aad[:], epoch)
	compressed, err := gcm.Open(nil, nonce, ciphertext, aad[:])
	if err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	return io.ReadAll(gz)
}

func TestSealDiffRoundTripsThroughTheReaderSteps(t *testing.T) {
	identity, err := EnsureIn(&memoryStore{}, "")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	body := []byte(`{"stat_summary":"+3 -1 across 2 file(s)","files":[{"path":"src/main.go"}]}`)

	sealed, err := SealDiff(identity, "/src/app", "/src/app", body)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if sealed.Version != envelopeVersion || sealed.Epoch != identity.Epoch {
		t.Fatalf("envelope must be self-describing: %+v", sealed)
	}

	opened := openDiffAsReader(t, identity.MCK, identity.Epoch, "/src/app", "/src/app", sealed)
	if string(opened) != string(body) {
		t.Fatalf("round trip changed the diff: %q", opened)
	}
}

// The whole point of sealing: what leaves the machine must not contain the
// patch. A ciphertext that still held the plaintext would pass every other
// test in this file.
func TestSealedCiphertextDoesNotContainThePlaintext(t *testing.T) {
	identity, _ := EnsureIn(&memoryStore{}, "")
	secret := "SUPER-SECRET-FUNCTION-NAME"
	body := []byte(`{"files":[{"patch":"` + secret + `"}]}`)

	sealed, err := SealDiff(identity, "/repo", "/repo", body)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	raw, _ := b64.DecodeString(sealed.Ciphertext)
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("plaintext survived into the ciphertext")
	}
	if bytes.Contains([]byte(sealed.Ciphertext), []byte(secret)) {
		t.Fatal("plaintext survived into the encoded envelope")
	}
}

// K_wt binds both paths, so the server cannot move one worktree's ciphertext
// into another's slot and have it decrypt. Key separation is what does the
// work an AAD binding of the paths would otherwise have to.
func TestWorktreeKeysAreSeparatedByPath(t *testing.T) {
	identity, _ := EnsureIn(&memoryStore{}, "")
	body := []byte(`{"files":[]}`)

	sealed, err := SealDiff(identity, "/src/app", "/src/app/wt-a", body)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	for name, paths := range map[string][2]string{
		"other worktree": {"/src/app", "/src/app/wt-b"},
		"other repo":     {"/src/other", "/src/app/wt-a"},
		// Length-prefixing is what stops these two colliding: without it,
		// "/a" + "/bc" and "/ab" + "/c" concatenate identically.
		"regrouped paths": {"/src/app/wt", "-a"},
	} {
		t.Run(name, func(t *testing.T) {
			key, err := deriveWorktreeKey(identity, paths[0], paths[1])
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			if _, err := openWithKey(key, identity.Epoch, sealed); err == nil {
				t.Fatal("a different worktree's key must not open this ciphertext")
			}
		})
	}
}

// Another machine's key must not open this one's diffs -- MCK is per-machine,
// which is what makes a grant meaningful.
func TestAnotherMachineCannotOpenTheDiff(t *testing.T) {
	mine, _ := EnsureIn(&memoryStore{}, "")
	theirs, _ := EnsureIn(&memoryStore{}, "")

	sealed, err := SealDiff(mine, "/repo", "/repo", []byte(`{"files":[]}`))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	key, _ := deriveWorktreeKey(theirs, "/repo", "/repo")
	if _, err := openWithKey(key, theirs.Epoch, sealed); err == nil {
		t.Fatal("another machine's content key must not open this ciphertext")
	}
}

// The epoch is in the AAD so a relabelled envelope fails loudly rather than
// decrypting to garbage the reader would then try to parse.
func TestEpochIsAuthenticated(t *testing.T) {
	identity, _ := EnsureIn(&memoryStore{}, "")
	sealed, err := SealDiff(identity, "/repo", "/repo", []byte(`{"files":[]}`))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	key, _ := deriveWorktreeKey(identity, "/repo", "/repo")
	if _, err := openWithKey(key, identity.Epoch+1, sealed); err == nil {
		t.Fatal("an envelope opened under another epoch must fail authentication")
	}
}

// Compress then seal, in that order. Sealed bytes are indistinguishable from
// random and do not compress, so the reverse order would cost CPU for nothing
// -- and this is the property that makes MAX_SEALED_BYTES carry several times
// its own weight in plaintext.
func TestDiffIsCompressedBeforeSealing(t *testing.T) {
	identity, _ := EnsureIn(&memoryStore{}, "")
	repetitive := bytes.Repeat([]byte("the same line over and over\n"), 500)

	sealed, err := SealDiff(identity, "/repo", "/repo", repetitive)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if sealed.DecodedLen() >= len(repetitive) {
		t.Fatalf("expected compression before sealing: %d sealed bytes for %d plaintext",
			sealed.DecodedLen(), len(repetitive))
	}
}

// A fresh nonce per seal, so two identical diffs do not produce identical
// ciphertext -- otherwise the server could tell that a worktree had reverted
// to a state it held before, which is content it is not supposed to learn.
func TestSealingTheSameDiffTwiceProducesDifferentCiphertext(t *testing.T) {
	identity, _ := EnsureIn(&memoryStore{}, "")
	body := []byte(`{"files":[{"patch":"same"}]}`)

	first, _ := SealDiff(identity, "/repo", "/repo", body)
	second, _ := SealDiff(identity, "/repo", "/repo", body)

	if first.Nonce == second.Nonce {
		t.Fatal("nonce must be fresh per seal")
	}
	if first.Ciphertext == second.Ciphertext {
		t.Fatal("identical diffs must not produce identical ciphertext")
	}
}

// The content token is what the server compares to decide whether anything
// changed, so it must move with the content and not with the encryption.
func TestContentTokenTracksContentNotCiphertext(t *testing.T) {
	identity, _ := EnsureIn(&memoryStore{}, "")
	body := []byte(`{"files":[{"patch":"one"}]}`)

	if ContentToken(identity, body) != ContentToken(identity, body) {
		t.Fatal("the same diff must fingerprint identically, or every heartbeat looks like a change")
	}
	if ContentToken(identity, body) == ContentToken(identity, []byte(`{"files":[{"patch":"two"}]}`)) {
		t.Fatal("a changed diff must fingerprint differently, or the settle clock never moves")
	}
}

// Keyed under MTK, which never rotates, so a future MCK rotation does not
// change every worktree's fingerprint at once and fire a settle notification
// per repo for work nobody touched.
func TestContentTokenIsIndependentOfTheContentKey(t *testing.T) {
	identity, _ := EnsureIn(&memoryStore{}, "")
	body := []byte(`{"files":[]}`)
	before := ContentToken(identity, body)

	rekeyed := &Identity{InstanceID: identity.InstanceID, MCK: make([]byte, keyLen), MTK: identity.MTK, Epoch: identity.Epoch + 1}
	if ContentToken(rekeyed, body) != before {
		t.Fatal("rotating the content key must not change content tokens")
	}
}

// Two machines with byte-identical diffs must not share a token: it would tell
// the server their working trees matched, which is content.
func TestContentTokensAreMachineScoped(t *testing.T) {
	mine, _ := EnsureIn(&memoryStore{}, "")
	theirs, _ := EnsureIn(&memoryStore{}, "")
	body := []byte(`{"files":[]}`)

	if ContentToken(mine, body) == ContentToken(theirs, body) {
		t.Fatal("two machines must not fingerprint the same diff identically")
	}
}

// A clean worktree needs a stable, non-empty token: the server reads an empty
// one as "unknown" and never compares it, so a worktree going clean would look
// like nothing happened.
func TestCleanTokenIsStableAndNotEmpty(t *testing.T) {
	identity, _ := EnsureIn(&memoryStore{}, "")
	clean := CleanContentToken(identity)

	if clean == "" {
		t.Fatal("a clean worktree must still carry a token")
	}
	if clean != CleanContentToken(identity) {
		t.Fatal("the clean token must be stable for a machine")
	}
	if clean == ContentToken(identity, []byte(`{"files":[{"patch":"x"}]}`)) {
		t.Fatal("clean must not collide with a real diff")
	}
}
