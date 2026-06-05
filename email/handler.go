package email

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"orion-auth-backend/audit"
	"orion-auth-backend/middleware"
	"orion-auth-backend/pkg"
)

// Handler exposes the admin CRUD + preview endpoints backing the
// WYSIWYG email template editor in the AdminUI.
type Handler struct {
	store        Store
	resolver     *Resolver
	auditService *audit.Service
}

func NewHandler(store Store, resolver *Resolver) *Handler {
	return &Handler{store: store, resolver: resolver}
}

func (h *Handler) SetAuditService(a *audit.Service) { h.auditService = a }

// RegisterAdminRoutes mounts the routes under an admin RouterGroup
// already gated by BearerAuth + the email_templates RBAC permission
// (wired in main.go).
func (h *Handler) RegisterAdminRoutes(admin *gin.RouterGroup) {
	admin.GET("/email-templates", h.List)
	admin.GET("/email-templates/:name", h.Get)
	admin.PUT("/email-templates/:name", h.Upsert)
	admin.POST("/email-templates/:name/preview", h.Preview)
	admin.DELETE("/email-templates/:name", h.Delete)
}

// templateListItem is the per-row payload returned by List. customized
// is the cheap signal the AdminUI uses to render a "Customized" badge
// without fetching the full body.
type templateListItem struct {
	Name       string   `json:"name"`
	Subject    string   `json:"subject"`
	Variables  []string `json:"variables"`
	Customized bool     `json:"customized"`
}

func (h *Handler) List(c *gin.Context) {
	items := make([]templateListItem, 0, len(TemplateNames()))
	for _, name := range TemplateNames() {
		subject, _, customized, err := h.resolver.Resolve(name)
		if err != nil {
			pkg.HandleError(c, pkg.ErrInternal("resolve template "+name+": "+err.Error()))
			return
		}
		items = append(items, templateListItem{
			Name:       name,
			Subject:    subject,
			Variables:  VariablesFor(name),
			Customized: customized,
		})
	}
	pkg.OK(c, gin.H{"templates": items})
}

// templateDetail surfaces everything the AdminUI needs to render the
// form: the current effective subject/body, the corresponding defaults
// (so the Reset button can preview what would be restored), and the
// allowed variable surface.
type templateDetail struct {
	Name            string   `json:"name"`
	Subject         string   `json:"subject"`
	BodyHTML        string   `json:"body_html"`
	DefaultSubject  string   `json:"default_subject"`
	DefaultBodyHTML string   `json:"default_body_html"`
	Variables       []string `json:"variables"`
	Customized      bool     `json:"customized"`
}

func (h *Handler) Get(c *gin.Context) {
	name := c.Param("name")
	if !knownTemplate(name) {
		pkg.HandleError(c, pkg.ErrNotFound("unknown template: "+name))
		return
	}
	subject, body, customized, err := h.resolver.Resolve(name)
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal(err.Error()))
		return
	}
	defaultBody, err := DefaultBody(name)
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal(err.Error()))
		return
	}
	pkg.OK(c, templateDetail{
		Name:            name,
		Subject:         subject,
		BodyHTML:        body,
		DefaultSubject:  DefaultSubject(name),
		DefaultBodyHTML: defaultBody,
		Variables:       VariablesFor(name),
		Customized:      customized,
	})
}

// upsertInput accepts the subject + body from the editor. Both are
// required: we don't store partial overrides (the resolver's "missing
// row = use default" semantics depends on the row either existing
// fully or not at all).
type upsertInput struct {
	Subject  string `json:"subject" binding:"required"`
	BodyHTML string `json:"body_html" binding:"required"`
}

func (h *Handler) Upsert(c *gin.Context) {
	name := c.Param("name")
	if !knownTemplate(name) {
		pkg.HandleError(c, pkg.ErrNotFound("unknown template: "+name))
		return
	}
	var input upsertInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	// Fail-fast on invalid template syntax. Catches the most common
	// edit-time bug (typo'd {{...}}) before it crashes at send time.
	if err := ParseCheck(name, input.BodyHTML); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("template syntax error: "+err.Error()))
		return
	}

	userID, _ := middleware.GetUserID(c)
	if err := h.store.Upsert(name, Override{Subject: input.Subject, BodyHTML: input.BodyHTML}, userID); err != nil {
		pkg.HandleError(c, pkg.ErrInternal(err.Error()))
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionEmailTemplateUpdated, map[string]any{
			"name":      name,
			"body_size": len(input.BodyHTML),
		})
	}
	pkg.OK(c, gin.H{"name": name, "customized": true})
}

// previewInput renders an unsaved draft with stub data. Lets the admin
// click "Preview" inside the editor without persisting first — the
// stub values are the same ones documented in the editor's variable
// helper so what the admin sees here matches what an end user will get.
type previewInput struct {
	Subject  string `json:"subject" binding:"required"`
	BodyHTML string `json:"body_html" binding:"required"`
}

type previewOutput struct {
	Subject  string `json:"subject"`
	BodyHTML string `json:"body_html"`
}

func (h *Handler) Preview(c *gin.Context) {
	name := c.Param("name")
	if !knownTemplate(name) {
		pkg.HandleError(c, pkg.ErrNotFound("unknown template: "+name))
		return
	}
	var input previewInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	stub := EmailData{
		Issuer:   "https://auth.example.test",
		Token:    "preview-token-12345",
		NewEmail: "preview@example.test",
	}
	// Parse + execute here (NOT via the resolver) because the input is
	// the unsaved draft, not the persisted override. Errors propagate
	// so the AdminUI can surface them inline.
	tpl, err := parsePreview(name, input.BodyHTML)
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("template syntax error: "+err.Error()))
		return
	}
	body, err := execPreview(tpl, stub)
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("template runtime error: "+err.Error()))
		return
	}
	pkg.OK(c, previewOutput{Subject: input.Subject, BodyHTML: body})
}

func (h *Handler) Delete(c *gin.Context) {
	name := c.Param("name")
	if !knownTemplate(name) {
		pkg.HandleError(c, pkg.ErrNotFound("unknown template: "+name))
		return
	}
	if err := h.store.Delete(name); err != nil {
		pkg.HandleError(c, pkg.ErrInternal(err.Error()))
		return
	}
	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionEmailTemplateReset, map[string]any{
			"name": name,
		})
	}
	c.Status(http.StatusNoContent)
}

func knownTemplate(name string) bool {
	for _, n := range TemplateNames() {
		if n == name {
			return true
		}
	}
	return false
}
