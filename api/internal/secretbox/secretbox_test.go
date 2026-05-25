package secretbox

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key := []byte("test-key-do-not-use-in-production")
	plaintext := []byte(`{"access_key_id":"AKIA...","secret_access_key":"…"}`)

	sealed, err := Seal(key, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if sealed == "" {
		t.Fatal("Seal returned empty string")
	}

	opened, err := Open(key, sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", opened, plaintext)
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	sealed, err := Seal([]byte("key-A"), []byte("hello"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open([]byte("key-B"), sealed); err == nil {
		t.Fatal("Open with wrong key must fail")
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	key := []byte("k")
	sealed, err := Seal(key, []byte("hello"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Flip a single character somewhere in the middle of the blob.
	b := []byte(sealed)
	b[len(b)/2] ^= 0x01
	if _, err := Open(key, string(b)); err == nil {
		t.Fatal("Open with tampered ciphertext must fail")
	}
}

func TestSealRejectsEmptyKey(t *testing.T) {
	if _, err := Seal(nil, []byte("x")); err == nil {
		t.Fatal("Seal with nil key must fail")
	}
}

func TestNoncesAreUnique(t *testing.T) {
	key := []byte("k")
	a, _ := Seal(key, []byte("same"))
	b, _ := Seal(key, []byte("same"))
	if a == b {
		t.Fatal("two Seals of identical plaintext produced identical output — nonce reuse")
	}
}
