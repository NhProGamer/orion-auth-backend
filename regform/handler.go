package regform

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/audit"
	"orion-auth-backend/pkg"
)

type Handler struct {
	service      *Service
	auditService *audit.Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) SetAuditService(s *audit.Service) {
	h.auditService = s
}

// RegisterAdminRoutes wires the admin-side CRUD + reorder endpoints.
func (h *Handler) RegisterAdminRoutes(admin *gin.RouterGroup) {
	admin.GET("/registration-fields", h.List)
	admin.GET("/registration-fields/:id", h.Get)
	admin.POST("/registration-fields", h.Create)
	admin.PATCH("/registration-fields/:id", h.Update)
	admin.DELETE("/registration-fields/:id", h.Delete)
	admin.PATCH("/registration-fields/reorder", h.Reorder)
}

// RegisterPublicRoutes wires the read-only schema endpoint consumed
// by the AuthUI for /register and /complete-account.
func (h *Handler) RegisterPublicRoutes(public *gin.RouterGroup) {
	public.GET("/auth/registration-fields", h.PublicList)
}

// --- Admin handlers

func (h *Handler) List(c *gin.Context) {
	items, err := h.service.List()
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	pkg.List(c, items, len(items))
}

func (h *Handler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid id"))
		return
	}
	f, err := h.service.Get(id)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	pkg.OK(c, gin.H{"field": f})
}

func (h *Handler) Create(c *gin.Context) {
	var in CreateInput
	if err := c.ShouldBindJSON(&in); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid body: "+err.Error()))
		return
	}
	f, err := h.service.Create(in)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionRegFormFieldCreated, map[string]any{
			"field_id":  f.ID,
			"field_key": f.FieldKey,
			"kind":      f.Kind,
			"type":      f.Type,
		})
	}
	pkg.Created(c, gin.H{"field": f})
}

func (h *Handler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid id"))
		return
	}
	var in UpdateInput
	if err := c.ShouldBindJSON(&in); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid body: "+err.Error()))
		return
	}
	f, err := h.service.Update(id, in)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionRegFormFieldUpdated, map[string]any{
			"field_id": f.ID,
		})
	}
	pkg.OK(c, gin.H{"field": f})
}

func (h *Handler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid id"))
		return
	}
	if err := h.service.Delete(id); err != nil {
		pkg.HandleError(c, err)
		return
	}
	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionRegFormFieldDeleted, map[string]any{"field_id": id})
	}
	pkg.OK(c, gin.H{"message": "deleted"})
}

func (h *Handler) Reorder(c *gin.Context) {
	var in ReorderInput
	if err := c.ShouldBindJSON(&in); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid body: "+err.Error()))
		return
	}
	if err := h.service.Reorder(in); err != nil {
		pkg.HandleError(c, err)
		return
	}
	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionRegFormFieldsReordered, map[string]any{
			"count": len(in.IDs),
		})
	}
	pkg.OK(c, gin.H{"message": "reordered"})
}

// --- Public handler

func (h *Handler) PublicList(c *gin.Context) {
	context := c.Query("context")
	if context == "" {
		context = "register"
	}
	items, err := h.service.ListForContext(context)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	pkg.OK(c, gin.H{"fields": items})
}
