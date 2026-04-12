package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const defaultTokenBytes = 32

// GenerateOpaqueToken generates a cryptographically random opaque token.
// Returns the raw token (to send to client) and its SHA-256 hash (to store in DB).
func GenerateOpaqueToken() (raw string, hash string, err error) {
	b := make([]byte, defaultTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("failed to generate token: %w", err)
	}

	raw = base64.RawURLEncoding.EncodeToString(b)
	hash = HashToken(raw)
	return raw, hash, nil
}

// HashToken returns the SHA-256 hex digest of the given token.
// Used to store tokens securely in the database.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// GenerateRandomString generates a URL-safe random string of the given byte length.
func GenerateRandomString(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
