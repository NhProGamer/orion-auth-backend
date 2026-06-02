package oidc

import (
	"os"
	"strings"
	"testing"

	"orion-auth-backend/pkg/netsafety"
)

// TestMain relaxes the JWKS URL validator so encryption_test can serve
// keys via a plain-http httptest.Server on loopback. Production callers
// continue to receive the strict netsafety check.
func TestMain(m *testing.M) {
	restore := SetJWKSURLValidatorForTest(func(raw string) error {
		if strings.HasPrefix(raw, "http://127.0.0.1") || strings.HasPrefix(raw, "http://localhost") {
			return nil
		}
		return netsafety.ValidatePublicHTTPSURL(raw)
	})
	defer restore()
	os.Exit(m.Run())
}
