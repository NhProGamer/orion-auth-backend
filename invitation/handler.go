package invitation

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/audit"
	"orion-auth-backend/middleware"
	"orion-auth-backend/pkg"
)

// FederationProviderInfo is the public-safe info for a federation provider.
type FederationProviderInfo struct {
	Name        string  `json:"name"`
	DisplayName *string `json:"display_name,omitempty"`
	Type        string  `json:"type"`
}

// FederationLister lists active federation providers (avoids circular import).
type FederationLister interface {
	ListActiveProviders() ([]FederationProviderInfo, error)
}

type Handler struct {
	service          *Service
	auditService     *audit.Service
	federationLister FederationLister
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) SetAuditService(s *audit.Service) {
	h.auditService = s
}

func (h *Handler) SetFederationLister(fl FederationLister) {
	h.federationLister = fl
}

func (h *Handler) RegisterPublicRoutes(public *gin.RouterGroup) {
	public.POST("/auth/register/invite", h.RegisterWithInvite)
	public.GET("/auth/settings", h.PublicSettings)
}

// PublicSettings godoc
// @Summary      Get public registration settings
// @Tags         Invitations
// @Produce      json
// @Success      200 {object} map[string]any
// @Router       /api/v1/auth/settings [get]
func (h *Handler) PublicSettings(c *gin.Context) {
	resp := gin.H{
		"registration_enabled": h.service.IsRegistrationEnabled(),
	}

	if h.federationLister != nil {
		providers, err := h.federationLister.ListActiveProviders()
		if err == nil {
			resp["federation_providers"] = providers
		} else {
			resp["federation_providers"] = []FederationProviderInfo{}
		}
	} else {
		resp["federation_providers"] = []FederationProviderInfo{}
	}

	pkg.OK(c, resp)
}

func (h *Handler) RegisterAdminRoutes(admin *gin.RouterGroup) {
	admin.POST("/invitations", h.Create)
	admin.GET("/invitations", h.List)
	admin.DELETE("/invitations/:id", h.Delete)
	admin.GET("/settings", h.GetSettings)
	admin.PATCH("/settings", h.UpdateSettings)
}

// Create godoc
// @Summary      Create an invitation
// @Tags         Admin - Invitations
// @Accept       json
// @Produce      json
// @Param        body body invitation.CreateInput true "Invitation creation payload"
// @Success      201 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      401 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/invitations [post]
func (h *Handler) Create(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}

	var input CreateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	inv, err := h.service.Create(input, userID)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionInvitationCreated, map[string]any{
			"invitation_id": inv.ID,
			"email":         input.Email,
		})
	}

	c.JSON(http.StatusCreated, gin.H{"invitation": inv})
}

// List godoc
// @Summary      List invitations
// @Tags         Admin - Invitations
// @Produce      json
// @Param        page query int false "Page number"
// @Param        per_page query int false "Items per page"
// @Success      200 {object} pkg.PaginatedResponse
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/invitations [get]
func (h *Handler) List(c *gin.Context) {
	page, perPage := pkg.ParsePagination(c)

	invitations, total, err := h.service.List(page, perPage)
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to list invitations"))
		return
	}

	pkg.Paginated(c, invitations, total, page, perPage)
}

// Delete godoc
// @Summary      Delete an invitation
// @Tags         Admin - Invitations
// @Produce      json
// @Param        id path string true "Invitation ID"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/invitations/{id} [delete]
func (h *Handler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid invitation ID"))
		return
	}

	if err := h.service.Delete(id); err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{"message": "invitation deleted"})
}

// RegisterWithInvite godoc
// @Summary      Register a new user with an invitation code
// @Tags         Invitations
// @Accept       json
// @Produce      json
// @Param        body body invitation.RegisterInviteInput true "Registration payload"
// @Success      201 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Router       /api/v1/auth/register/invite [post]
func (h *Handler) RegisterWithInvite(c *gin.Context) {
	var input RegisterInviteInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	user, err := h.service.RegisterWithInvite(input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{"user": user.PublicProfile()})
}

// GetSettings godoc
// @Summary      Get all application settings
// @Tags         Admin - Settings
// @Produce      json
// @Success      200 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/settings [get]
func (h *Handler) GetSettings(c *gin.Context) {
	settings, err := h.service.GetAllSettings()
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{"settings": settings})
}

type UpdateSettingsInput struct {
	RegistrationEnabled *bool `json:"registration_enabled"`
}

// UpdateSettings godoc
// @Summary      Update application settings
// @Tags         Admin - Settings
// @Accept       json
// @Produce      json
// @Param        body body invitation.UpdateSettingsInput true "Settings update payload"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/settings [patch]
func (h *Handler) UpdateSettings(c *gin.Context) {
	var input UpdateSettingsInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	if input.RegistrationEnabled != nil {
		val := "false"
		if *input.RegistrationEnabled {
			val = "true"
		}
		if err := h.service.UpdateSetting("registration_enabled", val); err != nil {
			pkg.HandleError(c, err)
			return
		}

		if h.auditService != nil {
			h.auditService.LogFromContext(c, audit.ActionSettingsUpdated, map[string]any{
				"registration_enabled": *input.RegistrationEnabled,
			})
		}
	}

	settings, err := h.service.GetAllSettings()
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{"settings": settings})
}
