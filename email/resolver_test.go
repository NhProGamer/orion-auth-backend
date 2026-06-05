package email

import (
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// fakeStore is a memory-only Store that the resolver test consumes.
// Tracks Get call count so we can verify the resolver cache prevents
// hammering the DB.
type fakeStore struct {
	mu        sync.Mutex
	overrides map[string]*Override
	getCalls  map[string]int
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		overrides: map[string]*Override{},
		getCalls:  map[string]int{},
	}
}

func (s *fakeStore) Get(name string) (*Override, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getCalls[name]++
	if ov, ok := s.overrides[name]; ok {
		return ov, nil
	}
	return nil, nil
}

func (s *fakeStore) Upsert(name string, ov Override, _ uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cpy := ov
	s.overrides[name] = &cpy
	return nil
}

func (s *fakeStore) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.overrides, name)
	return nil
}

func (s *fakeStore) List() ([]Summary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Summary, 0, len(s.overrides))
	for name, ov := range s.overrides {
		out = append(out, Summary{Name: name, Subject: ov.Subject})
	}
	return out, nil
}

func TestResolver_FallbackToEmbed(t *testing.T) {
	r := NewResolver(newFakeStore())
	subject, body, customized, err := r.Resolve("verification")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if customized {
		t.Error("customized should be false when store has no row")
	}
	if subject != "Verify your email address" {
		t.Errorf("subject = %q, want default", subject)
	}
	if !strings.Contains(body, "{{.Token}}") {
		t.Errorf("embedded body should still contain raw template placeholder")
	}
}

func TestResolver_DBOverrideWins(t *testing.T) {
	store := newFakeStore()
	store.overrides["verification"] = &Override{
		Subject:  "Custom subject",
		BodyHTML: "<p>Hello {{.Token}}</p>",
	}
	r := NewResolver(store)
	subject, body, customized, err := r.Resolve("verification")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !customized {
		t.Error("customized should be true when store has a row")
	}
	if subject != "Custom subject" {
		t.Errorf("subject = %q, want override", subject)
	}
	if body != "<p>Hello {{.Token}}</p>" {
		t.Errorf("body not from override: %q", body)
	}
}

func TestResolver_Render_ExecutesPlaceholders(t *testing.T) {
	store := newFakeStore()
	store.overrides["verification"] = &Override{
		Subject:  "Verify {{.Token}}",
		BodyHTML: "<p>Hello {{.Token}} from {{.Issuer}}</p>",
	}
	r := NewResolver(store)
	subject, body, err := r.Render("verification", EmailData{
		Issuer: "https://auth.example.test",
		Token:  "abc",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	// Subject is NOT templated here — only the body is. If subject
	// templating ever ships, this test must update.
	if subject != "Verify {{.Token}}" {
		t.Errorf("subject = %q (raw, not executed by design)", subject)
	}
	if body != "<p>Hello abc from https://auth.example.test</p>" {
		t.Errorf("body = %q", body)
	}
}

func TestResolver_ParseCacheReusedAcrossRenders(t *testing.T) {
	store := newFakeStore()
	r := NewResolver(store)
	for i := 0; i < 5; i++ {
		if _, _, err := r.Render("verification", EmailData{Issuer: "x", Token: "t"}); err != nil {
			t.Fatalf("Render: %v", err)
		}
	}
	if got := len(r.parsedCache); got != 1 {
		t.Errorf("parsedCache size = %d, want 1 (single entry reused)", got)
	}
}

func TestResolver_ParseCacheInvalidatedOnBodyChange(t *testing.T) {
	store := newFakeStore()
	r := NewResolver(store)
	// First render via embed default — caches one entry.
	_, _, err := r.Render("verification", EmailData{Issuer: "x", Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(r.parsedCache); got != 1 {
		t.Fatalf("cache size after first render = %d, want 1", got)
	}

	// Admin saves an override → next Render reparses, old entry evicted.
	store.overrides["verification"] = &Override{Subject: "x", BodyHTML: "<p>{{.Token}}</p>"}
	_, _, err = r.Render("verification", EmailData{Issuer: "x", Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(r.parsedCache); got != 1 {
		t.Errorf("cache size after override = %d, want 1 (old entry evicted)", got)
	}
}

func TestParseCheck_RejectsBadSyntax(t *testing.T) {
	if err := ParseCheck("verification", "<p>{{.Token"); err == nil {
		t.Error("ParseCheck should reject unterminated action")
	}
	if err := ParseCheck("verification", "<p>{{.Token}}</p>"); err != nil {
		t.Errorf("ParseCheck rejected valid template: %v", err)
	}
}

func TestVariablesFor_KnownTemplates(t *testing.T) {
	if got := VariablesFor("verification"); len(got) != 2 {
		t.Errorf("verification variables = %v, want 2", got)
	}
	if got := VariablesFor("unknown"); got != nil {
		t.Errorf("unknown template should return nil, got %v", got)
	}
}

func TestTemplateNames_AllHaveDefaults(t *testing.T) {
	for _, name := range TemplateNames() {
		if DefaultSubject(name) == "" {
			t.Errorf("template %q has no default subject", name)
		}
		if _, err := DefaultBody(name); err != nil {
			t.Errorf("template %q has no default body: %v", name, err)
		}
		if VariablesFor(name) == nil {
			t.Errorf("template %q has no variables list", name)
		}
	}
}
