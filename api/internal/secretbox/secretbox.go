// Package secretbox is an envelope-encryption helper for credential
// blobs stored alongside connector rows. It uses AES-256-GCM with a key
// derived (via SHA-256) from TOUCHSTONE_SECRET_KEY, so rotating the
// secret key invalidates every sealed blob — by design.
//
// When the deployment grows past a single-node Compose stack, replace
// the implementation with a KMS / Vault Transit / Azure KV envelope.
// The exported Seal / Open signatures intentionally hide the cipher
// choice so callers don't need to change.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// Seal encrypts plaintext under key. Output is base64 (no padding) of
// nonce || ciphertext-with-tag, safe to drop into a TEXT column.
func Seal(key, plaintext []byte) (string, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("secretbox: read nonce: %w", err)
	}
	ct := aead.Seal(nonce, nonce, plaintext, nil)
	return base64.RawStdEncoding.EncodeToString(ct), nil
}

// Open decrypts a blob produced by Seal. Returns an error if the key
// is wrong, the blob is corrupt, or the GCM tag fails to verify.
func Open(key []byte, sealed string) ([]byte, error) {
	raw, err := base64.RawStdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("secretbox: decode: %w", err)
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(raw) < aead.NonceSize() {
		return nil, errors.New("secretbox: blob too short")
	}
	nonce, ct := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("secretbox: open: %w", err)
	}
	return pt, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) == 0 {
		return nil, errors.New("secretbox: key is empty")
	}
	sum := sha256.Sum256(key)
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, fmt.Errorf("secretbox: cipher: %w", err)
	}
	return cipher.NewGCM(block)
}
