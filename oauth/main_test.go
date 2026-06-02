package oauth

import (
	"os"
	"strings"
	"testing"

	"orion-auth-backend/middleware"
	"orion-auth-backend/pkg/netsafety"
)

// TestMain relaxes the JWKS URL validator used by middleware.fetchJWKS so
// request_object_test can serve keys over a plain-http httptest.Server.
// Production callers continue to receive the strict netsafety check.
func TestMain(m *testing.M) {
	restore := middleware.SetJWKSURLValidatorForTest(func(raw string) error {
		if strings.HasPrefix(raw, "http://127.0.0.1") || strings.HasPrefix(raw, "http://localhost") {
			return nil
		}
		return netsafety.ValidatePublicHTTPSURL(raw)
	})
	defer restore()
	os.Exit(m.Run())
}
