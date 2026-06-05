package email

import (
	"bytes"
	"strings"
	"testing"
)

// TestAllTemplatesRender locks down the embed.FS template set — if any
// .gohtml file is added with a syntax error, parsing tmpl at package
// init would already panic; this test surfaces missing template files
// or missing EmailData fields BEFORE production hits them on the hot
// path (verify-email, password reset, account deletion).
func TestAllTemplatesRender(t *testing.T) {
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
			template: "verification.gohtml",
			wantContains: []string{
				"https://auth.example.test/api/v1/auth/verify-email?token=tok_abc123",
			},
		},
		{
			template:     "password_reset.gohtml",
			wantContains: []string{"tok_abc123", "https://auth.example.test"},
		},
		{
			template:     "invitation.gohtml",
			wantContains: []string{"tok_abc123", "https://auth.example.test"},
		},
		{
			template:     "account_email_change.gohtml",
			wantContains: []string{"tok_abc123"},
		},
		{
			template:     "account_email_changed.gohtml",
			wantContains: []string{"new@example.test"},
		},
		{
			template:     "account_password_changed.gohtml",
			wantContains: []string{"https://auth.example.test"},
		},
		{
			template:     "account_deletion.gohtml",
			wantContains: []string{"tok_abc123"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.template, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tmpl.ExecuteTemplate(&buf, tc.template, data); err != nil {
				t.Fatalf("render: %v", err)
			}
			body := buf.String()
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

// TestSendVerificationEmail_TemplateInlining is the round-trip view:
// it exercises the same path as the Send* methods (template lookup +
// data plumbing) without dialing SMTP. If a future refactor moves
// rendering into a helper, this test should follow.
func TestSendVerificationEmail_TemplateInlining(t *testing.T) {
	var buf bytes.Buffer
	err := tmpl.ExecuteTemplate(&buf, "verification.gohtml", EmailData{
		Issuer: "https://auth.example.test",
		Token:  "secret-token-value",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()
	// The Token is sensitive — confirm it ends up in the body exactly
	// once, namely inside the verify-email URL. Multiple occurrences
	// would suggest accidental leakage in HTML attributes / footer.
	if strings.Count(body, "secret-token-value") != 1 {
		t.Errorf("token appears %d times, want exactly 1 (in the verify URL).\nbody=%s",
			strings.Count(body, "secret-token-value"), body)
	}
}
