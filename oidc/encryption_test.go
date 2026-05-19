package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func generateRSAKeyPair(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func newEncJWKSServer(t *testing.T, kid string, pub *rsa.PublicKey, use string) *httptest.Server {
	t.Helper()
	keyMap := map[string]any{
		"kid": kid,
		"kty": "RSA",
		"alg": "RSA-OAEP-256",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
	if use != "" {
		keyMap["use"] = use
	}
	body := map[string]any{"keys": []any{keyMap}}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(body)
	}))
}

func TestEncryptForClient_RoundTrip(t *testing.T) {
	resetJWEJWKSCacheForTest()
	priv := generateRSAKeyPair(t)
	srv := newEncJWKSServer(t, "rp-key-1", &priv.PublicKey, "enc")
	defer srv.Close()

	s := setActiveKeyWithPub(t)
	payload := []byte("hello world")

	encrypted, err := s.EncryptForClient(payload, srv.URL, "RSA-OAEP-256", "A256GCM")
	if err != nil {
		t.Fatalf("EncryptForClient: %v", err)
	}
	// JWE compact serialization has 5 segments.
	if got := strings.Count(encrypted, "."); got != 4 {
		t.Errorf("JWE should have 4 dots (5 segments), got %d in %q", got, encrypted)
	}

	// Decrypt with the RP's private key to confirm it actually worked.
	rpKey, err := jwk.Import(priv)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := jwe.Decrypt([]byte(encrypted), jwe.WithKey(jwa.RSA_OAEP_256(), rpKey))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(decrypted) != string(payload) {
		t.Errorf("decrypted payload mismatch: %q != %q", decrypted, payload)
	}
}

func TestEncryptForClient_RejectsUnsupportedAlg(t *testing.T) {
	resetJWEJWKSCacheForTest()
	s := setActiveKeyWithPub(t)
	if _, err := s.EncryptForClient([]byte("x"), "http://nope", "BOGUS", "A256GCM"); err == nil {
		t.Errorf("expected unsupported alg failure")
	}
}

func TestEncryptForClient_RejectsMissingJWKSURI(t *testing.T) {
	resetJWEJWKSCacheForTest()
	s := setActiveKeyWithPub(t)
	if _, err := s.EncryptForClient([]byte("x"), "", "RSA-OAEP-256", "A256GCM"); err == nil {
		t.Errorf("expected error on empty jwks_uri")
	}
}

func TestPickEncryptionKey_SkipsUseSig(t *testing.T) {
	resetJWEJWKSCacheForTest()
	priv := generateRSAKeyPair(t)
	srv := newEncJWKSServer(t, "sig-key", &priv.PublicKey, "sig")
	defer srv.Close()

	s := setActiveKeyWithPub(t)
	if _, err := s.EncryptForClient([]byte("x"), srv.URL, "RSA-OAEP-256", "A256GCM"); err == nil {
		t.Errorf("expected failure when only use=sig keys exist in JWKS")
	}
}

func TestValidateJWEEncryptionPair(t *testing.T) {
	cases := []struct {
		name    string
		alg     string
		enc     string
		wantErr bool
	}{
		{"both empty ok", "", "", false},
		{"alg only", "RSA-OAEP-256", "", true},
		{"enc only", "", "A256GCM", true},
		{"both supported", "RSA-OAEP-256", "A256GCM", false},
		{"unsupported alg", "FOO", "A256GCM", true},
		{"unsupported enc", "RSA-OAEP-256", "BAR", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateJWEEncryptionPair(tc.alg, tc.enc)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}
