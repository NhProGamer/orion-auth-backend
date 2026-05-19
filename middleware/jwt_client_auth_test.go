package middleware

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const testTokenEndpoint = "https://auth.example.com/token"

func signClientSecretJWT(t *testing.T, clientID uuid.UUID, aud string, hmacKey []byte, mutators ...func(jwt.MapClaims)) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": clientID.String(),
		"sub": clientID.String(),
		"aud": aud,
		"jti": uuid.NewString(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(2 * time.Minute).Unix(),
	}
	for _, m := range mutators {
		m(claims)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(hmacKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func TestValidateClientSecretJWT_Valid(t *testing.T) {
	cid := uuid.New()
	hmacKey := []byte("super-secret-key-thats-32-bytes!")
	jwtStr := signClientSecretJWT(t, cid, testTokenEndpoint, hmacKey)

	got, err := ValidateClientSecretJWT(jwtStr, testTokenEndpoint, hmacKey)
	if err != nil {
		t.Fatalf("ValidateClientSecretJWT: %v", err)
	}
	if got != cid {
		t.Errorf("client id = %s, want %s", got, cid)
	}
}

func TestValidateClientSecretJWT_WrongSignature(t *testing.T) {
	cid := uuid.New()
	hmacKey := []byte("super-secret-key-thats-32-bytes!")
	other := []byte("DIFFERENT-key-thats-also-32-bytes")
	jwtStr := signClientSecretJWT(t, cid, testTokenEndpoint, hmacKey)

	if _, err := ValidateClientSecretJWT(jwtStr, testTokenEndpoint, other); err == nil {
		t.Errorf("expected signature failure with mismatched key")
	}
}

func TestValidateClientSecretJWT_NoKey(t *testing.T) {
	cid := uuid.New()
	jwtStr := signClientSecretJWT(t, cid, testTokenEndpoint, []byte("k"))
	if _, err := ValidateClientSecretJWT(jwtStr, testTokenEndpoint, nil); err == nil {
		t.Errorf("expected error when hmac key is nil")
	}
}

func TestValidateClientSecretJWT_Expired(t *testing.T) {
	cid := uuid.New()
	hmacKey := []byte("super-secret-key-thats-32-bytes!")
	jwtStr := signClientSecretJWT(t, cid, testTokenEndpoint, hmacKey, func(c jwt.MapClaims) {
		c["exp"] = time.Now().Add(-1 * time.Minute).Unix()
	})
	if _, err := ValidateClientSecretJWT(jwtStr, testTokenEndpoint, hmacKey); err == nil {
		t.Errorf("expected expiration failure")
	}
}

func TestValidateClientSecretJWT_WrongAudience(t *testing.T) {
	cid := uuid.New()
	hmacKey := []byte("super-secret-key-thats-32-bytes!")
	jwtStr := signClientSecretJWT(t, cid, "https://malicious.example/token", hmacKey)
	if _, err := ValidateClientSecretJWT(jwtStr, testTokenEndpoint, hmacKey); err == nil || !strings.Contains(err.Error(), "aud") {
		t.Errorf("expected aud mismatch, got %v", err)
	}
}

func TestValidateClientSecretJWT_MissingJTI(t *testing.T) {
	cid := uuid.New()
	hmacKey := []byte("super-secret-key-thats-32-bytes!")
	jwtStr := signClientSecretJWT(t, cid, testTokenEndpoint, hmacKey, func(c jwt.MapClaims) {
		delete(c, "jti")
	})
	if _, err := ValidateClientSecretJWT(jwtStr, testTokenEndpoint, hmacKey); err == nil || !strings.Contains(err.Error(), "jti") {
		t.Errorf("expected jti error, got %v", err)
	}
}

func TestValidateClientSecretJWT_RejectsRSAToken(t *testing.T) {
	cid := uuid.New()
	hmacKey := []byte("super-secret-key-thats-32-bytes!")
	// Forge a header with alg=RS256 but sign with HMAC anyway — the parsed
	// SigningMethod will be RSA and we should reject before signature check.
	claims := jwt.MapClaims{
		"iss": cid.String(),
		"sub": cid.String(),
		"aud": testTokenEndpoint,
		"jti": uuid.NewString(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["alg"] = "RS256"
	// Sign with HMAC even though header lies about alg — golang-jwt encodes
	// the header as-is.
	signed, err := tok.SignedString(hmacKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateClientSecretJWT(signed, testTokenEndpoint, hmacKey); err == nil {
		t.Errorf("expected rejection when JWT header alg is not HMAC")
	} else if !errors.Is(err, err) {
		// just ensure we got an error
	}
}
