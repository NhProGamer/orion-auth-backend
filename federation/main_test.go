package federation

import (
	"net"
	"os"
	"strings"
	"testing"

	"orion-auth-backend/pkg/netsafety"
)

// TestMain installs two pieces of test scaffolding for the federation
// package:
//
//  1. A stub DNS resolver so netsafety.ValidatePublicHTTPSURL accepts
//     fake hostnames like accounts.example.com (RFC 5737 mapping).
//  2. A relaxed URL validator that ALSO accepts http://127.0.0.1 — the
//     integration tests spin up an httptest IdP on plain http loopback,
//     which would otherwise be refused as SSRF-prone.
//
// Both relaxations are scoped to the test binary; production code paths
// continue to require https + public addresses.
func TestMain(m *testing.M) {
	restoreResolver := netsafety.SetResolverForTest(stubTestResolver{})
	restoreValidator := SetURLValidatorForTest(testURLValidator)
	defer restoreResolver()
	defer restoreValidator()
	os.Exit(m.Run())
}

// testURLValidator wraps the production validator but lets http://127.0.0.1
// and http://localhost pass — httptest.Server URLs always look like that.
func testURLValidator(raw string) error {
	if strings.HasPrefix(raw, "http://127.0.0.1") || strings.HasPrefix(raw, "http://localhost") {
		return nil
	}
	return netsafety.ValidatePublicHTTPSURL(raw)
}

type stubTestResolver struct{}

// LookupIP resolves any hostname containing a dot to the RFC 5737 example
// IP. Loopback / private literals continue to flow through the validator's
// IP-direct check and stay refused. Anything that does not look like a
// real hostname is left unresolved so we still surface bugs in tests that
// pass garbage URLs.
func (stubTestResolver) LookupIP(host string) ([]net.IP, error) {
	if !strings.Contains(host, ".") {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return []net.IP{net.ParseIP("203.0.113.1")}, nil
}
