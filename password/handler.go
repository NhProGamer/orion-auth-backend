package password

import (
	"github.com/gin-gonic/gin"

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

// RegisterPublicRoutes mounts the no-auth read endpoint that the AuthUI
// uses to render its registration / reset / change-password screens.
// The policy is public information by nature (visible in any UI hint).
func (h *Handler) RegisterPublicRoutes(public *gin.RouterGroup) {
	public.GET("/password-policy", h.GetPublic)
}

// RegisterAdminRoutes mounts the read+write endpoints under /api/v1/admin.
// Caller is responsible for the RBAC gate (same as /admin/settings).
func (h *Handler) RegisterAdminRoutes(admin *gin.RouterGroup) {
	admin.GET("/password-policy", h.GetAdmin)
	admin.PATCH("/password-policy", h.Update)
}

// GetPublic godoc
// @Summary      Get the active password policy
// @Tags         Password Policy
// @Produce      json
// @Success      200 {object} map[string]any
// @Router       /api/v1/password-policy [get]
func (h *Handler) GetPublic(c *gin.Context) {
	pkg.OK(c, gin.H{"policy": h.service.Get()})
}

// GetAdmin godoc
// @Summary      Get the active password policy (admin)
// @Tags         Admin - Password Policy
// @Produce      json
// @Success      200 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/password-policy [get]
func (h *Handler) GetAdmin(c *gin.Context) {
	pkg.OK(c, gin.H{"policy": h.service.Get()})
}

// Update godoc
// @Summary      Replace the password policy
// @Tags         Admin - Password Policy
// @Accept       json
// @Produce      json
// @Param        body body password.Policy true "Full policy"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/password-policy [patch]
func (h *Handler) Update(c *gin.Context) {
	var input Policy
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	if err := h.service.Update(input); err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to persist password policy"))
		return
	}

	saved := h.service.Get()
	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionPasswordPolicyUpdated, map[string]any{
			"min_length":        saved.MinLength,
			"max_length":        saved.MaxLength,
			"require_uppercase": saved.RequireUpper,
			"require_lowercase": saved.RequireLower,
			"require_digit":     saved.RequireDigit,
			"require_symbol":    saved.RequireSymbol,
			"min_score":         saved.MinScore,
		})
	}
	pkg.OK(c, gin.H{"policy": saved})
}
