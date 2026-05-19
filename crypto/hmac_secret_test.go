package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func mustEncKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestEncryptDecryptHMACSecret_RoundTrip(t *testing.T) {
	encKey := mustEncKey(t)
	plain, _, err := GenerateHMACSecret()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := EncryptHMACSecret(plain, encKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := DecryptHMACSecret(sealed, encKey)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(plain, got) {
		t.Errorf("round-trip mismatch")
	}
}

func TestDecryptHMACSecret_WrongKeyFails(t *testing.T) {
	plain, _, _ := GenerateHMACSecret()
	sealed, _ := EncryptHMACSecret(plain, mustEncKey(t))
	if _, err := DecryptHMACSecret(sealed, mustEncKey(t)); err == nil {
		t.Errorf("expected decrypt to fail with wrong key")
	}
}

func TestEncryptHMACSecret_RejectsBadKeyLen(t *testing.T) {
	if _, err := EncryptHMACSecret([]byte("x"), make([]byte, 16)); err == nil {
		t.Errorf("expected error on 16-byte key")
	}
}

func TestDecodeHMACEncryptionKey(t *testing.T) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	for _, enc := range []string{
		base64.StdEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw),
		base64.RawURLEncoding.EncodeToString(raw),
	} {
		got, err := DecodeHMACEncryptionKey(enc)
		if err != nil {
			t.Errorf("decode %q failed: %v", enc, err)
			continue
		}
		if !bytes.Equal(got, raw) {
			t.Errorf("decode %q mismatch", enc)
		}
	}

	if _, err := DecodeHMACEncryptionKey("not-base64-$$"); err == nil {
		t.Errorf("expected error on bad base64")
	}
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	if _, err := DecodeHMACEncryptionKey(short); err == nil {
		t.Errorf("expected error on 16-byte key")
	}
}

func TestGenerateHMACSecret_Length(t *testing.T) {
	raw, b64, err := GenerateHMACSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != HMACSecretBytes {
		t.Errorf("len = %d", len(raw))
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(b64); err != nil || !bytes.Equal(decoded, raw) {
		t.Errorf("b64 round-trip failed")
	}
}
