package netsafety

import (
	"errors"
	"net"
	"testing"
)

// stubResolver returns canned LookupIP responses keyed by host.
type stubResolver struct {
	answers map[string][]net.IP
	err     error
}

func (s stubResolver) LookupIP(host string) ([]net.IP, error) {
	if s.err != nil {
		return nil, s.err
	}
	if ips, ok := s.answers[host]; ok {
		return ips, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestValidatePublicHTTPSURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		dns     map[string][]net.IP
		wantErr error // exact sentinel, or nil
	}{
		{
			name:    "valid https with public IP",
			url:     "https://example.com/.well-known/jwks.json",
			dns:     map[string][]net.IP{"example.com": {net.ParseIP("93.184.216.34")}},
			wantErr: nil,
		},
		{
			name:    "valid https IP literal",
			url:     "https://93.184.216.34/jwks",
			wantErr: nil,
		},
		{
			name:    "rejects http scheme",
			url:     "http://example.com/jwks",
			wantErr: ErrInvalidScheme,
		},
		{
			name:    "rejects ftp scheme",
			url:     "ftp://example.com/jwks",
			wantErr: ErrInvalidScheme,
		},
		{
			name:    "rejects loopback IPv4 literal",
			url:     "https://127.0.0.1/jwks",
			wantErr: ErrPrivateAddress,
		},
		{
			name:    "rejects loopback IPv6 literal",
			url:     "https://[::1]/jwks",
			wantErr: ErrPrivateAddress,
		},
		{
			name:    "rejects RFC1918 10.x literal",
			url:     "https://10.0.0.1/jwks",
			wantErr: ErrPrivateAddress,
		},
		{
			name:    "rejects RFC1918 172.16.x literal",
			url:     "https://172.16.0.1/jwks",
			wantErr: ErrPrivateAddress,
		},
		{
			name:    "rejects RFC1918 192.168.x literal",
			url:     "https://192.168.1.1/jwks",
			wantErr: ErrPrivateAddress,
		},
		{
			name:    "rejects link-local 169.254.x literal (AWS IMDS)",
			url:     "https://169.254.169.254/latest/meta-data/iam/security-credentials/",
			wantErr: ErrPrivateAddress,
		},
		{
			name:    "rejects CGNAT 100.64/10 literal",
			url:     "https://100.64.1.1/jwks",
			wantErr: ErrPrivateAddress,
		},
		{
			name:    "rejects 0.0.0.0 literal",
			url:     "https://0.0.0.0/jwks",
			wantErr: ErrPrivateAddress,
		},
		{
			name:    "rejects unique-local IPv6 (fc00::/7)",
			url:     "https://[fc00::1]/jwks",
			wantErr: ErrPrivateAddress,
		},
		{
			name:    "rejects link-local IPv6 (fe80::/10)",
			url:     "https://[fe80::1]/jwks",
			wantErr: ErrPrivateAddress,
		},
		{
			name:    "rejects literal 'localhost' even without DNS",
			url:     "https://localhost/jwks",
			wantErr: ErrPrivateAddress,
		},
		{
			name:    "rejects hostname resolving to loopback",
			url:     "https://attacker.example/jwks",
			dns:     map[string][]net.IP{"attacker.example": {net.ParseIP("127.0.0.1")}},
			wantErr: ErrPrivateAddress,
		},
		{
			name:    "rejects hostname resolving to RFC1918",
			url:     "https://internal.example/jwks",
			dns:     map[string][]net.IP{"internal.example": {net.ParseIP("10.0.0.5")}},
			wantErr: ErrPrivateAddress,
		},
		{
			name:    "rejects hostname with mixed public + private (DNS rebinding defence)",
			url:     "https://mixed.example/jwks",
			dns:     map[string][]net.IP{"mixed.example": {net.ParseIP("93.184.216.34"), net.ParseIP("10.0.0.1")}},
			wantErr: ErrPrivateAddress,
		},
		{
			name:    "rejects empty host",
			url:     "https:///jwks",
			wantErr: ErrMalformedURL,
		},
		{
			name:    "rejects malformed URL",
			url:     "://broken",
			wantErr: ErrMalformedURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := SetResolverForTest(stubResolver{answers: tt.dns})
			defer restore()
			err := ValidatePublicHTTPSURL(tt.url)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("expected nil error, got %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestValidateRedirectURIScheme(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr error
	}{
		{"https any host accepted", "https://app.example.com/cb", nil},
		{"http loopback IPv4 accepted", "http://127.0.0.1:8080/cb", nil},
		{"http loopback IPv6 accepted", "http://[::1]:8080/cb", nil},
		{"http localhost accepted", "http://localhost:3000/cb", nil},
		{"http remote refused", "http://attacker.example/cb", ErrInvalidScheme},
		{"javascript refused", "javascript:alert(1)", ErrInvalidScheme},
		{"data: refused", "data:text/html,<script>alert(1)</script>", ErrInvalidScheme},
		{"vbscript refused", "vbscript:msgbox(1)", ErrInvalidScheme},
		{"file:// refused", "file:///etc/passwd", ErrInvalidScheme},
		{"ftp refused", "ftp://example.com/", ErrInvalidScheme},
		{"reverse-dns native scheme accepted", "com.example.app:/oauth/cb", nil},
		{"io.foo.bar native scheme accepted", "io.foo.bar:/cb", nil},
		{"bare scheme without dot refused", "myapp:/cb", ErrInvalidScheme},
		{"missing scheme refused", "/cb", ErrMalformedURL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRedirectURIScheme(tt.uri)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("expected nil error, got %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}
