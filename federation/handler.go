package federation

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/audit"
	"orion-auth-backend/middleware"
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

// RegisterPublicRoutes registers federation endpoints that don't require auth.
func (h *Handler) RegisterPublicRoutes(public *gin.RouterGroup) {
	public.GET("/auth/federation/:provider", h.InitSocialLogin)
	public.POST("/auth/federation/:provider/callback", h.Callback)
}

// RegisterAuthenticatedRoutes registers endpoints that require auth.
func (h *Handler) RegisterAuthenticatedRoutes(authenticated *gin.RouterGroup) {
	authenticated.GET("/me/linked-accounts", h.ListLinkedAccounts)
	authenticated.DELETE("/me/linked-accounts/:id", h.UnlinkAccount)
}

// RegisterAdminRoutes registers admin CRUD for federation providers.
func (h *Handler) RegisterAdminRoutes(admin *gin.RouterGroup) {
	admin.POST("/federation", h.CreateProvider)
	admin.GET("/federation", h.ListProviders)
	admin.PATCH("/federation/:id", h.UpdateProvider)
	admin.DELETE("/federation/:id", h.DeleteProvider)
}

// InitSocialLogin godoc
// @Summary      Initiate social login via a federation provider
// @Tags         Federation
// @Produce      json
// @Param        provider path string true "Provider name"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Router       /api/v1/auth/federation/{provider} [get]
func (h *Handler) InitSocialLogin(c *gin.Context) {
	providerName := c.Param("provider")

	authURL, err := h.service.InitSocialLogin(providerName)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{"authorization_url": authURL})
}

// Callback godoc
// @Summary      Handle federation provider callback
// @Tags         Federation
// @Accept       json
// @Produce      json
// @Param        provider path string true "Provider name"
// @Param        body body federation.CallbackInput true "Callback payload"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Router       /api/v1/auth/federation/{provider}/callback [post]
func (h *Handler) Callback(c *gin.Context) {
	providerName := c.Param("provider")

	var input CallbackInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	// Check if user is authenticated (for account linking)
	var userID *uuid.UUID
	if uid, ok := middleware.GetUserID(c); ok {
		userID = &uid
	}

	result, err := h.service.ProcessCallback(providerName, input, userID)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, result)
}

// ListLinkedAccounts godoc
// @Summary      List linked federation accounts for the current user
// @Tags         Federation
// @Produce      json
// @Success      200 {object} map[string]any
// @Failure      401 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/me/linked-accounts [get]
func (h *Handler) ListLinkedAccounts(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}

	links, err := h.service.GetLinkedAccounts(userID)
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to list linked accounts"))
		return
	}

	pkg.OK(c, gin.H{"linked_accounts": links})
}

// UnlinkAccount godoc
// @Summary      Unlink a federation account
// @Tags         Federation
// @Produce      json
// @Param        id path string true "Linked account ID"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      401 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/me/linked-accounts/{id} [delete]
func (h *Handler) UnlinkAccount(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}

	linkID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid link ID"))
		return
	}

	if err := h.service.UnlinkAccount(linkID, userID); err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{"message": "account unlinked"})
}

// --- Admin ---

// CreateProvider godoc
// @Summary      Create a federation provider
// @Tags         Admin - Federation
// @Accept       json
// @Produce      json
// @Param        body body federation.CreateProviderInput true "Provider creation payload"
// @Success      201 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/federation [post]
func (h *Handler) CreateProvider(c *gin.Context) {
	var input CreateProviderInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	p, err := h.service.CreateProvider(input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionFederationProviderCreated, map[string]any{
			"provider_id":   p.ID,
			"provider_name": p.Name,
		})
	}

	pkg.Created(c, gin.H{"provider": p})
}

// ListProviders godoc
// @Summary      List all federation providers
// @Tags         Admin - Federation
// @Produce      json
// @Success      200 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/federation [get]
func (h *Handler) ListProviders(c *gin.Context) {
	providers, err := h.service.ListProviders()
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to list providers"))
		return
	}
	pkg.OK(c, gin.H{"providers": providers})
}

// UpdateProvider godoc
// @Summary      Update a federation provider
// @Tags         Admin - Federation
// @Accept       json
// @Produce      json
// @Param        id path string true "Provider ID"
// @Param        body body federation.UpdateProviderInput true "Provider update payload"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/federation/{id} [patch]
func (h *Handler) UpdateProvider(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid provider ID"))
		return
	}
	var input UpdateProviderInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	p, err := h.service.UpdateProvider(id, input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionFederationProviderUpdated, map[string]any{
			"provider_id": id,
		})
	}

	pkg.OK(c, gin.H{"provider": p})
}

// DeleteProvider godoc
// @Summary      Delete a federation provider
// @Tags         Admin - Federation
// @Produce      json
// @Param        id path string true "Provider ID"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/federation/{id} [delete]
func (h *Handler) DeleteProvider(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid provider ID"))
		return
	}
	if err := h.service.DeleteProvider(id); err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionFederationProviderDeleted, map[string]any{
			"provider_id": id,
		})
	}

	pkg.OK(c, gin.H{"message": "provider deleted"})
}
