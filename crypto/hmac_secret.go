package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// HMACSecretBytes is the length of the raw HMAC key generated per client and
// used for client_secret_jwt (HS256) assertions.
const HMACSecretBytes = 32

// GenerateHMACSecret returns a cryptographically random 32-byte key suitable
// for HMAC-SHA256, plus its URL-safe base64 representation for one-time
// return to the client at creation/rotation.
func GenerateHMACSecret() (raw []byte, b64 string, err error) {
	raw = make([]byte, HMACSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", fmt.Errorf("failed to generate hmac secret: %w", err)
	}
	return raw, base64.RawURLEncoding.EncodeToString(raw), nil
}

// EncryptHMACSecret seals an HMAC key with the server-side AES-256-GCM key.
// The wire format is: [12-byte nonce][ciphertext+tag].
// encryptionKey must be exactly 32 bytes (AES-256).
func EncryptHMACSecret(plaintext, encryptionKey []byte) ([]byte, error) {
	if len(encryptionKey) != 32 {
		return nil, errors.New("encryption key must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// DecryptHMACSecret reverses EncryptHMACSecret.
func DecryptHMACSecret(ciphered, encryptionKey []byte) ([]byte, error) {
	if len(encryptionKey) != 32 {
		return nil, errors.New("encryption key must be 32 bytes (AES-256)")
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonceSize := gcm.NonceSize()
	if len(ciphered) < nonceSize+gcm.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, body := ciphered[:nonceSize], ciphered[nonceSize:]
	return gcm.Open(nil, nonce, body, nil)
}

// DecodeHMACEncryptionKey parses a base64-encoded AES-256 key from config.
// Accepts standard and URL-safe encodings, with or without padding.
func DecodeHMACEncryptionKey(encoded string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if key, err := enc.DecodeString(encoded); err == nil {
			if len(key) != 32 {
				return nil, fmt.Errorf("hmac encryption key must decode to 32 bytes, got %d", len(key))
			}
			return key, nil
		}
	}
	return nil, errors.New("hmac encryption key is not valid base64")
}
