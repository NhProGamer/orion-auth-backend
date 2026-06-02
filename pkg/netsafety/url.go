// Package netsafety provides URL/host validation helpers used by every code
// path that fetches a remote URL on behalf of an untrusted caller — typically
// jwks_uri / issuer_url / userinfo_url supplied via Dynamic Client
// Registration or the federation admin API.
//
// The two main entry points are:
//
//   - ValidatePublicHTTPSURL: refuses anything that resolves to a private,
//     loopback, link-local, unspecified or multicast address, and anything
//     that is not https.
//
//   - ValidateRedirectURIScheme: refuses XSS-vectors (javascript:, data:,
//     vbscript:, …) on OAuth redirect_uris while allowing the standard
//     RFC 8252 native-app schemes and the loopback exception.
package netsafety

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ErrPrivateAddress is returned when a URL resolves to an address that must
// not be reachable from a user-controlled fetch (RFC 1918, loopback, link-
// local, unspecified, multicast, CGNAT).
var ErrPrivateAddress = errors.New("URL resolves to a non-public address")

// ErrInvalidScheme is returned when a URL uses a scheme that is not allowed
// for the given context.
var ErrInvalidScheme = errors.New("URL scheme is not allowed")

// ErrMalformedURL covers parse failures and missing hostnames.
var ErrMalformedURL = errors.New("URL is malformed")

// resolver is the DNS resolver used by ValidatePublicHTTPSURL. Tests swap it
// out via SetResolverForTest so they can simulate poisoned DNS without
// touching the real network.
var resolver hostResolver = netResolver{}

type hostResolver interface {
	LookupIP(host string) ([]net.IP, error)
}

type netResolver struct{}

func (netResolver) LookupIP(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

// SetResolverForTest swaps the DNS resolver used by ValidatePublicHTTPSURL.
// Returns a restore function. Not safe for concurrent use.
func SetResolverForTest(r hostResolver) func() {
	prev := resolver
	resolver = r
	return func() { resolver = prev }
}

// ValidatePublicHTTPSURL returns nil iff raw parses as a well-formed https
// URL whose hostname resolves exclusively to public IP addresses. Any IP in
// the private/loopback/link-local/unspecified/multicast/CGNAT ranges causes
// the call to fail — this is the core SSRF defence applied to jwks_uri,
// issuer_url, userinfo_url, etc.
//
// IPv6 literals are resolved through the same checks (::1 loopback, fc00::/7
// unique-local, fe80::/10 link-local, ff00::/8 multicast).
func ValidatePublicHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedURL, err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("%w: scheme must be https, got %q", ErrInvalidScheme, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: missing host", ErrMalformedURL)
	}

	// If the host is a literal IP we can check directly without DNS.
	if ip := net.ParseIP(host); ip != nil {
		if !isPublicIP(ip) {
			return fmt.Errorf("%w: %s", ErrPrivateAddress, ip)
		}
		return nil
	}

	// "localhost" deserves an explicit message rather than a DNS surprise.
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("%w: localhost", ErrPrivateAddress)
	}

	ips, err := resolver.LookupIP(host)
	if err != nil {
		return fmt.Errorf("dns lookup for %q failed: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("dns lookup for %q returned no addresses", host)
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return fmt.Errorf("%w: %s resolves to %s", ErrPrivateAddress, host, ip)
		}
	}
	return nil
}

// isPublicIP returns true iff ip is a globally routable unicast address.
// We refuse loopback, multicast, unspecified, link-local, RFC 1918 private,
// the CGNAT 100.64/10 range and IPv4 broadcast — all of which would let an
// attacker probe internal infrastructure via a server-side fetch.
func isPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip.IsPrivate() {
		return false
	}
	// CGNAT 100.64.0.0/10 is not flagged by IsPrivate.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xC0 == 0x40 {
			return false
		}
		// 0.0.0.0/8 is reserved.
		if v4[0] == 0 {
			return false
		}
		// 255.255.255.255 broadcast.
		if v4.Equal(net.IPv4bcast) {
			return false
		}
	}
	return true
}

// ValidateRedirectURIScheme validates the scheme of an OAuth redirect_uri
// against the OAuth 2.1 / RFC 8252 allowlist.
//
// Accepted schemes:
//   - "https" with any host (the dominant production case)
//   - "http" only when the host is exactly "localhost" or 127.0.0.1[:port]
//     (loopback exception for native apps and local development)
//   - Any non-"http"/"https" scheme containing a "." is treated as a
//     native-app reverse-DNS scheme (e.g. "com.example.app", "io.foo.bar")
//     per RFC 8252 §7.1 and is allowed.
//
// Refused: javascript:, data:, vbscript:, file:, ftp:, ws[s]:, mailto:, …
// every legacy XSS vector and anything that does not name an HTTP endpoint
// or a registered native-app scheme.
func ValidateRedirectURIScheme(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedURL, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		return fmt.Errorf("%w: missing scheme", ErrMalformedURL)
	}
	switch scheme {
	case "https":
		if u.Host == "" {
			return fmt.Errorf("%w: https URL missing host", ErrMalformedURL)
		}
		return nil
	case "http":
		host := u.Hostname()
		if host == "127.0.0.1" || host == "::1" || strings.EqualFold(host, "localhost") {
			return nil
		}
		return fmt.Errorf("%w: http allowed only on loopback (127.0.0.1/localhost), got host %q", ErrInvalidScheme, host)
	case "javascript", "data", "vbscript", "file", "ftp", "ws", "wss", "mailto", "tel", "sms":
		return fmt.Errorf("%w: scheme %q is never allowed as a redirect_uri", ErrInvalidScheme, scheme)
	}
	// Reverse-DNS native scheme (RFC 8252 §7.1): must contain at least one
	// dot to look like a domain (e.g. com.example.app).
	if strings.Contains(scheme, ".") {
		return nil
	}
	return fmt.Errorf("%w: scheme %q is not an allowed redirect_uri scheme", ErrInvalidScheme, scheme)
}
