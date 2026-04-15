package crypto

import (
	"strings"
	"testing"

	"orion-auth-backend/config"
)

func newTestHasher() *Argon2Hasher {
	return NewArgon2Hasher(config.Argon2Config{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	})
}

func TestHashAndVerify(t *testing.T) {
	h := newTestHasher()

	hash, err := h.Hash("correct-password")
	if err != nil {
		t.Fatalf("Hash() error: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash should start with $argon2id$, got %s", hash)
	}

	ok, err := h.Verify("correct-password", hash)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if !ok {
		t.Error("Verify() should return true for correct password")
	}

	ok, err = h.Verify("wrong-password", hash)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if ok {
		t.Error("Verify() should return false for wrong password")
	}
}

func TestHashUniqueness(t *testing.T) {
	h := newTestHasher()

	hash1, _ := h.Hash("same-password")
	hash2, _ := h.Hash("same-password")

	if hash1 == hash2 {
		t.Error("two hashes of the same password should differ (unique salt)")
	}
}

func TestVerifyInvalidHash(t *testing.T) {
	h := newTestHasher()

	_, err := h.Verify("password", "not-a-valid-hash")
	if err == nil {
		t.Error("Verify() should return error for invalid hash")
	}
}
