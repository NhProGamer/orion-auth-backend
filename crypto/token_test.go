package crypto

import (
	"testing"
)

func TestGenerateOpaqueToken(t *testing.T) {
	raw, hash, err := GenerateOpaqueToken()
	if err != nil {
		t.Fatalf("GenerateOpaqueToken() error: %v", err)
	}

	if len(raw) == 0 {
		t.Error("raw token should not be empty")
	}
	if len(hash) != 64 {
		t.Errorf("hash should be 64 hex chars (SHA-256), got %d", len(hash))
	}

	// Hash should be deterministic for the same input
	if HashToken(raw) != hash {
		t.Error("HashToken(raw) should equal the returned hash")
	}
}

func TestGenerateOpaqueTokenUniqueness(t *testing.T) {
	raw1, _, _ := GenerateOpaqueToken()
	raw2, _, _ := GenerateOpaqueToken()

	if raw1 == raw2 {
		t.Error("two generated tokens should be different")
	}
}

func TestHashTokenDeterministic(t *testing.T) {
	h1 := HashToken("test-token")
	h2 := HashToken("test-token")

	if h1 != h2 {
		t.Error("HashToken should be deterministic")
	}
}

func TestGenerateRandomString(t *testing.T) {
	s, err := GenerateRandomString(16)
	if err != nil {
		t.Fatalf("GenerateRandomString() error: %v", err)
	}
	if len(s) == 0 {
		t.Error("random string should not be empty")
	}
}
