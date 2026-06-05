package email

import (
	"bytes"
	"fmt"
	"html/template"
	"log/slog"
	"sync"

	"orion-auth-backend/email/templates"
)

// Resolver is the single rendering entry point used by SMTPSender and
// OutboxSender. It looks up an admin override in the Store first, then
// falls back to the embedded default. Parsed templates are cached
// (keyed by content hash) so repeated sends don't pay the parsing cost.
type Resolver struct {
	store Store

	mu          sync.RWMutex
	parsedCache map[string]*template.Template // cache key = name + body content
}

// NewResolver wires the override Store. Pass a nil store to disable
// overrides entirely (the resolver then only serves embedded defaults
// — useful in early-boot diagnostics or tests that don't need the DB).
func NewResolver(store Store) *Resolver {
	return &Resolver{
		store:       store,
		parsedCache: make(map[string]*template.Template),
	}
}

// TemplateNames is the closed set of templates the system knows about.
// Editing the list requires shipping the corresponding .gohtml file in
// email/templates and a matching entry in defaultSubjects + variables.
func TemplateNames() []string {
	return []string{
		"verification",
		"password_reset",
		"invitation",
		"account_email_change",
		"account_email_changed",
		"account_password_changed",
		"account_deletion",
	}
}

// VariablesFor returns the list of EmailData fields that the template
// is allowed to reference. The AdminUI uses this to restrict the @-mention
// popup to a fixed surface; the backend uses it for safety so the
// validator can fail-fast on unknown references before they crash at
// send time.
func VariablesFor(name string) []string {
	if v, ok := variables[name]; ok {
		return v
	}
	return nil
}

var variables = map[string][]string{
	"verification":             {"Issuer", "Token"},
	"password_reset":           {"Issuer", "Token"},
	"invitation":               {"Issuer", "Token"},
	"account_email_change":     {"Issuer", "Token"},
	"account_email_changed":    {"Issuer", "NewEmail"},
	"account_password_changed": {"Issuer"},
	"account_deletion":         {"Issuer", "Token"},
}

// defaultSubjects centralises the subject strings previously hardcoded
// in smtp.go's per-Send method. Used both as fallback when the DB row
// has no override AND as the value returned by GET /email-templates/:name
// so the AdminUI can show "default: X" alongside an edited value.
var defaultSubjects = map[string]string{
	"verification":             "Verify your email address",
	"password_reset":           "Reset your password",
	"invitation":               "You've been invited",
	"account_email_change":     "Confirm your new email address",
	"account_email_changed":    "Your email address was changed",
	"account_password_changed": "Your password was changed",
	"account_deletion":         "Account deletion scheduled",
}

// DefaultSubject returns the hardcoded subject for a known template,
// or empty string if name is unknown.
func DefaultSubject(name string) string { return defaultSubjects[name] }

// DefaultBody reads the raw embedded body for a known template.
// Returns empty + error if the template file is missing — should never
// happen since the embed.FS is statically validated at build time.
func DefaultBody(name string) (string, error) {
	data, err := templates.FS.ReadFile(name + ".gohtml")
	if err != nil {
		return "", fmt.Errorf("read embedded template %q: %w", name, err)
	}
	return string(data), nil
}

// Render returns the subject + rendered HTML body for a template. It
// consults the Store first; on miss (or store=nil) it falls back to
// the embedded default subject + body.
func (r *Resolver) Render(name string, data EmailData) (subject, body string, err error) {
	subject, rawBody, err := r.resolve(name)
	if err != nil {
		return "", "", err
	}

	tpl, err := r.parsedFor(name, rawBody)
	if err != nil {
		return "", "", fmt.Errorf("parse template %q: %w", name, err)
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return "", "", fmt.Errorf("execute template %q: %w", name, err)
	}
	return subject, buf.String(), nil
}

// Resolve returns the raw subject + body that Render would use, without
// executing the template. The handler uses this to surface
// "default vs override" in the AdminUI.
func (r *Resolver) Resolve(name string) (subject, body string, customized bool, err error) {
	if r.store != nil {
		ov, err := r.store.Get(name)
		if err != nil {
			return "", "", false, err
		}
		if ov != nil {
			return ov.Subject, ov.BodyHTML, true, nil
		}
	}
	body, err = DefaultBody(name)
	if err != nil {
		return "", "", false, err
	}
	return DefaultSubject(name), body, false, nil
}

func (r *Resolver) resolve(name string) (string, string, error) {
	s, b, _, err := r.Resolve(name)
	return s, b, err
}

func (r *Resolver) parsedFor(name, body string) (*template.Template, error) {
	cacheKey := name + "\x00" + body

	r.mu.RLock()
	cached, ok := r.parsedCache[cacheKey]
	r.mu.RUnlock()
	if ok {
		return cached, nil
	}

	tpl, err := template.New(name).Parse(body)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	// Keep the cache from growing unbounded: drop everything else for
	// this name when a new body version appears (admin saved an edit).
	for k := range r.parsedCache {
		if len(k) > len(name) && k[:len(name)] == name && k[len(name)] == 0x00 {
			delete(r.parsedCache, k)
		}
	}
	r.parsedCache[cacheKey] = tpl
	r.mu.Unlock()

	slog.Debug("email template parsed and cached", "name", name, "bytes", len(body))
	return tpl, nil
}

// ParseCheck validates that a body is a syntactically-valid Go
// html/template. Used by the handler at PUT time to reject broken
// edits before they hit the DB. Does not execute the template — see
// Render with stub data for an end-to-end check.
func ParseCheck(name, body string) error {
	_, err := template.New(name).Parse(body)
	return err
}

// parsePreview / execPreview drive the /preview endpoint. They bypass
// the resolver's cache because the input is an unsaved draft that
// should not pollute the cache shared by live sends.
func parsePreview(name, body string) (*template.Template, error) {
	return template.New(name).Parse(body)
}

func execPreview(tpl *template.Template, data EmailData) (string, error) {
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
