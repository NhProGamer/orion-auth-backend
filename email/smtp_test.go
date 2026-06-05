package email

import (
	"strings"
	"testing"
)

// TestAllTemplatesRender exercises every shipped default template
// through the Resolver. If any .gohtml file is renamed, removed, or
// gains a syntax error, this fails fast — before production hits it on
// the verify-email / password-reset hot path.
func TestAllTemplatesRender(t *testing.T) {
	// Resolver with no Store → always serves embedded defaults.
	resolver := NewResolver(nil)
	data := EmailData{
		Issuer:   "https://auth.example.test",
		Token:    "tok_abc123",
		NewEmail: "new@example.test",
	}

	cases := []struct {
		template string
		// substrings the rendered body MUST contain. Encodes the wiring
		// contract between Send* methods and the .gohtml files: if a
		// template ever drops the verify URL, the link in the email
		// breaks silently in prod — this catches it.
		wantContains []string
	}{
		{
			template: "verification",
			wantContains: []string{
				"https://auth.example.test/api/v1/auth/verify-email?token=tok_abc123",
			},
		},
		{
			template:     "password_reset",
			wantContains: []string{"tok_abc123", "https://auth.example.test"},
		},
		{
			template:     "invitation",
			wantContains: []string{"tok_abc123", "https://auth.example.test"},
		},
		{
			template:     "account_email_change",
			wantContains: []string{"tok_abc123"},
		},
		{
			template:     "account_email_changed",
			wantContains: []string{"new@example.test"},
		},
		{
			template:     "account_password_changed",
			wantContains: []string{"https://auth.example.test"},
		},
		{
			template:     "account_deletion",
			wantContains: []string{"tok_abc123"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.template, func(t *testing.T) {
			subject, body, err := resolver.Render(tc.template, data)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if subject == "" {
				t.Error("subject is empty — default missing in resolver.defaultSubjects?")
			}
			if body == "" {
				t.Fatal("rendered body is empty")
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(body, want) {
					t.Errorf("body missing %q.\nbody=%s", want, body)
				}
			}
		})
	}
}

// TestRenderVerificationToken_NoLeakage confirms the token only shows
// up exactly once in the rendered body (inside the verify URL).
// Multiple occurrences would suggest accidental leakage into HTML
// attributes / footer / preview text.
func TestRenderVerificationToken_NoLeakage(t *testing.T) {
	resolver := NewResolver(nil)
	_, body, err := resolver.Render("verification", EmailData{
		Issuer: "https://auth.example.test",
		Token:  "secret-token-value",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Count(body, "secret-token-value") != 1 {
		t.Errorf("token appears %d times, want exactly 1.\nbody=%s",
			strings.Count(body, "secret-token-value"), body)
	}
}
