package crypto

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"

	"orion-auth-backend/config"
)

func testHasher() *Argon2Hasher {
	return NewArgon2Hasher(config.Argon2Config{
		Memory:      65536,
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	})
}

// argon2iHash builds a Logto-style Argon2i PHC string for the given password.
func argon2iHash(t *testing.T, password string) string {
	t.Helper()
	salt := []byte("0123456789abcdef")
	const (
		mem  = 65536
		iter = 3
		par  = 4
		klen = 32
	)
	key := argon2.Key([]byte(password), salt, iter, mem, par, klen)
	return fmt.Sprintf("$argon2i$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, mem, iter, par,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

func TestVerifyIdentify(t *testing.T) {
	h := testHasher()
	const pw = "correct horse battery staple"

	native, err := h.Hash(pw)
	if err != nil {
		t.Fatalf("native hash: %v", err)
	}

	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}

	sha256Digest := func(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }
	sha1Digest := func(s string) string { d := sha1.Sum([]byte(s)); return hex.EncodeToString(d[:]) }
	md5Digest := func(s string) string { d := md5.Sum([]byte(s)); return hex.EncodeToString(d[:]) }

	enc := func(method, digest string) string {
		s, err := EncodeForeignHash(method, digest)
		if err != nil {
			t.Fatalf("EncodeForeignHash(%s): %v", method, err)
		}
		return s
	}

	tests := []struct {
		name       string
		stored     string
		password   string
		wantOK     bool
		wantRehash bool
		wantErr    bool
	}{
		{"argon2id native match", native, pw, true, false, false},
		{"argon2id native mismatch", native, "wrong", false, false, false},
		{"argon2i match", argon2iHash(t, pw), pw, true, true, false},
		{"argon2i mismatch", argon2iHash(t, pw), "wrong", false, true, false},
		{"bcrypt match", string(bcryptHash), pw, true, true, false},
		{"bcrypt mismatch", string(bcryptHash), "wrong", false, true, false},
		{"sha256 match", enc("sha256", sha256Digest(pw)), pw, true, true, false},
		{"sha256 mismatch", enc("sha256", sha256Digest(pw)), "wrong", false, true, false},
		{"sha1 match", enc("sha1", sha1Digest(pw)), pw, true, true, false},
		{"md5 match", enc("md5", md5Digest(pw)), pw, true, true, false},
		{"unsupported scheme", "$legacy$[\"pbkdf2\",[]]", pw, false, false, true},
		{"garbage", "not-a-hash", pw, false, false, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, rehash, err := h.VerifyIdentify(tc.password, tc.stored)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got ok=%v rehash=%v", ok, rehash)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
			if rehash != tc.wantRehash {
				t.Errorf("needsRehash = %v, want %v", rehash, tc.wantRehash)
			}
		})
	}
}

func TestEncodeForeignHash(t *testing.T) {
	if _, err := EncodeForeignHash("sha512", "abcd"); err == nil {
		t.Error("expected error for unsupported method sha512")
	}
	if _, err := EncodeForeignHash("sha256", "nothex!!"); err == nil {
		t.Error("expected error for non-hex digest")
	}
	got, err := EncodeForeignHash("SHA256", "ABCDEF")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "$imported$sha256$abcdef" {
		t.Errorf("got %q, want normalized lowercase envelope", got)
	}
}

// Native argon2id must never report needsRehash, otherwise every login would
// rewrite the hash pointlessly.
func TestNativeNeverRehashes(t *testing.T) {
	h := testHasher()
	native, _ := h.Hash("whatever-123")
	_, rehash, err := h.VerifyIdentify("whatever-123", native)
	if err != nil {
		t.Fatal(err)
	}
	if rehash {
		t.Error("native argon2id should not need rehash")
	}
}
