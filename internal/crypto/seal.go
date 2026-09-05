package crypto

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// Sealing one worktree's diff, and fingerprinting its content.
//
// The server stores what this file produces and cannot open it. Everything it
// still runs on -- machine, repo, branch, magnitude, freshness -- travels in
// the clear beside the ciphertext; only the patch bodies are sealed.

const (
	// diffInfoPrefix domain-separates a worktree key from the grant KEK, which
	// is derived from the same MCK.
	diffInfoPrefix = "th/diff/v1"

	// tokenLen is the content token's length in bytes. Truncating the HMAC is
	// fine because the server only ever compares tokens for equality -- it
	// never inverts one, and a collision costs a missed change notification,
	// not a disclosure.
	tokenLen = 16

	// CleanContentToken is what a worktree with no diff fingerprints to.
	//
	// Deliberately not the empty string: the server reads an empty token as
	// "unknown" and never compares it, so a worktree going clean would look
	// like nothing happened and the settle clock would not move. It is still
	// HMACed under MTK rather than being a literal, so it stays a fixed value
	// per machine rather than a constant every machine shares.
	cleanTokenSeed = "th/clean/v1"
)

// SealedDiff is one worktree's encrypted diff, as it travels to the server.
//
// The server holds this and can do nothing with it but store and return it.
// Every derivation input the reader needs travels with the ciphertext, because
// the reader has only what the API hands it: the epoch selects the key, and
// the nonce is what AES-GCM needs to open it. The paths are not here -- they
// come from the overview, which the reader already has.
type SealedDiff struct {
	// Version is the envelope format, not the key epoch. The two move
	// independently, which is what lets a later format change (a sequence
	// number in the AAD, say) happen without a flag day.
	Version int `json:"v"`
	// Epoch selects K_wt and is also the AEAD's additional data, so an
	// envelope relabelled with another epoch fails to open rather than
	// decrypting to garbage.
	Epoch uint32 `json:"epoch"`
	Nonce string `json:"nonce"`
	// Ciphertext is AES-256-GCM output with the tag appended, over gzipped
	// JSON. Compress then seal, in that order and no other: sealed bytes are
	// indistinguishable from random and do not compress, so the other order
	// would cost CPU for nothing.
	Ciphertext string `json:"ct"`
}

// DecodedLen is the size of the ciphertext in bytes, before base64url
// expansion. This is what MAX_SEALED_BYTES is measured over -- see
// payload.MaxSealedBytes for why the wire size is a different number.
func (s SealedDiff) DecodedLen() int {
	return b64.DecodedLen(len(s.Ciphertext))
}

// deriveWorktreeKey produces the key one worktree's diffs are sealed under.
//
// repoPath and wtPath go in length-prefixed, so no two path pairs can produce
// the same derivation input by concatenating differently. They are used as
// exact octet strings: the reader re-derives from the values the overview
// returns, and any transformation of those bytes on either side -- trimming,
// case folding, separator rewriting, Unicode normalization -- yields a
// different key and a decryption failure with nothing to diagnose. The daemon
// therefore seals against exactly the bytes it sends.
func deriveWorktreeKey(identity *Identity, repoPath, wtPath string) ([]byte, error) {
	var salt [4]byte
	binary.BigEndian.PutUint32(salt[:], identity.Epoch)

	info := append([]byte(diffInfoPrefix), lengthPrefixed(repoPath, wtPath)...)
	key, err := hkdf.Key(sha256.New, identity.MCK, salt[:], string(info), keyLen)
	if err != nil {
		return nil, fmt.Errorf("derive worktree key: %w", err)
	}
	return key, nil
}

// SealDiff gzips diffJSON and encrypts the result for one worktree.
//
// It takes marshalled JSON rather than a struct because the same bytes are
// what ContentToken fingerprints: computing the token from a second
// marshalling would let an encoding difference make a worktree look changed
// when it had not.
func SealDiff(identity *Identity, repoPath, wtPath string, diffJSON []byte) (*SealedDiff, error) {
	key, err := deriveWorktreeKey(identity, repoPath, wtPath)
	if err != nil {
		return nil, err
	}

	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	if _, err := gw.Write(diffJSON); err != nil {
		return nil, fmt.Errorf("compress diff: %w", err)
	}
	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("compress diff: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	var aad [4]byte
	binary.BigEndian.PutUint32(aad[:], identity.Epoch)
	ciphertext := gcm.Seal(nil, nonce, compressed.Bytes(), aad[:])

	return &SealedDiff{
		Version:    envelopeVersion,
		Epoch:      identity.Epoch,
		Nonce:      b64.EncodeToString(nonce),
		Ciphertext: b64.EncodeToString(ciphertext),
	}, nil
}

// MarshalDiff is the one place a diff becomes bytes. SealDiff and ContentToken
// both consume its output so the sealed body and the fingerprint of it are
// always taken over identical bytes.
func MarshalDiff(diff any) ([]byte, error) {
	encoded, err := json.Marshal(diff)
	if err != nil {
		return nil, fmt.Errorf("encode diff: %w", err)
	}
	return encoded, nil
}

// ContentToken fingerprints a worktree's diff under MTK.
//
// MTK rather than MCK, deliberately: deriving this from the content key would
// make every worktree's fingerprint change the moment the machine re-keyed,
// which the server reads as "everything changed at once" and turns into a
// settle notification per repo for work nobody touched.
//
// Keyed rather than a bare hash so the value discloses nothing about the diff
// to whoever holds it. The server only ever compares it against the previous
// one; it never interprets it.
func ContentToken(identity *Identity, diffJSON []byte) string {
	mac := hmac.New(sha256.New, identity.MTK)
	mac.Write(diffJSON)
	return b64.EncodeToString(mac.Sum(nil)[:tokenLen])
}

// CleanContentToken is the fingerprint of a worktree with nothing to seal.
func CleanContentToken(identity *Identity) string {
	return ContentToken(identity, []byte(cleanTokenSeed))
}
