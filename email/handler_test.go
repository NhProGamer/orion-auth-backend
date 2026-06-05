package email

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func newTestRouter() (*gin.Engine, *fakeStore, *Resolver, *Handler) {
	gin.SetMode(gin.TestMode)
	store := newFakeStore()
	resolver := NewResolver(store)
	h := NewHandler(store, resolver)
	r := gin.New()
	admin := r.Group("/api/v1/admin")
	h.RegisterAdminRoutes(admin)
	return r, store, resolver, h
}

func TestHandler_List_ReturnsAllTemplates(t *testing.T) {
	r, _, _, _ := newTestRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/admin/email-templates", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Templates []templateListItem `json:"templates"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Templates) != len(TemplateNames()) {
		t.Errorf("got %d templates, want %d", len(body.Templates), len(TemplateNames()))
	}
	for _, item := range body.Templates {
		if item.Customized {
			t.Errorf("template %q should not be customized in fresh store", item.Name)
		}
		if len(item.Variables) == 0 {
			t.Errorf("template %q has empty variables list", item.Name)
		}
	}
}

func TestHandler_Get_UnknownReturns404(t *testing.T) {
	r, _, _, _ := newTestRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/admin/email-templates/does-not-exist", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d, want 404", w.Code)
	}
}

func TestHandler_Upsert_HappyPath(t *testing.T) {
	r, store, _, _ := newTestRouter()
	payload := upsertInput{
		Subject:  "Custom subject",
		BodyHTML: "<p>Hello {{.Token}}</p>",
	}
	body, _ := json.Marshal(payload)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPut, "/api/v1/admin/email-templates/verification", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	ov := store.overrides["verification"]
	if ov == nil {
		t.Fatal("override not persisted in store")
	}
	if ov.Subject != "Custom subject" {
		t.Errorf("subject = %q", ov.Subject)
	}
}

func TestHandler_Upsert_RejectsSyntaxError(t *testing.T) {
	r, store, _, _ := newTestRouter()
	payload := upsertInput{
		Subject:  "x",
		BodyHTML: "<p>{{.Token", // unterminated action
	}
	body, _ := json.Marshal(payload)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPut, "/api/v1/admin/email-templates/verification", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 (body=%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "syntax") {
		t.Errorf("response should mention syntax error, got %s", w.Body.String())
	}
	if store.overrides["verification"] != nil {
		t.Error("override should NOT be persisted on syntax error")
	}
}

func TestHandler_Preview_RendersWithStubData(t *testing.T) {
	r, _, _, _ := newTestRouter()
	payload := previewInput{
		Subject:  "x",
		BodyHTML: "<p>Hello {{.Token}} from {{.Issuer}}</p>",
	}
	body, _ := json.Marshal(payload)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/admin/email-templates/verification/preview", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var out previewOutput
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Stub data is documented in handler.Preview; lock it down so the
	// AdminUI's "Preview" docs stay in sync.
	if !strings.Contains(out.BodyHTML, "preview-token-12345") {
		t.Errorf("preview should render with stub token, body=%s", out.BodyHTML)
	}
	if !strings.Contains(out.BodyHTML, "https://auth.example.test") {
		t.Errorf("preview should render with stub issuer, body=%s", out.BodyHTML)
	}
}

func TestHandler_Delete_ClearsOverride(t *testing.T) {
	r, store, _, _ := newTestRouter()
	// Seed an override
	store.overrides["verification"] = &Override{Subject: "x", BodyHTML: "<p>y</p>"}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodDelete, "/api/v1/admin/email-templates/verification", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if store.overrides["verification"] != nil {
		t.Error("override should be cleared after DELETE")
	}
}
