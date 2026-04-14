package invitation

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/middleware"
	"orion-auth-backend/pkg"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterPublicRoutes(public *gin.RouterGroup) {
	public.POST("/auth/register/invite", h.RegisterWithInvite)
	public.GET("/auth/settings", h.PublicSettings)
}

func (h *Handler) PublicSettings(c *gin.Context) {
	pkg.OK(c, gin.H{
		"registration_enabled": h.service.IsRegistrationEnabled(),
	})
}

func (h *Handler) RegisterAdminRoutes(admin *gin.RouterGroup) {
	admin.POST("/invitations", h.Create)
	admin.GET("/invitations", h.List)
	admin.DELETE("/invitations/:id", h.Delete)
	admin.GET("/settings", h.GetSettings)
	admin.PATCH("/settings", h.UpdateSettings)
}

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

	c.JSON(http.StatusCreated, gin.H{"invitation": inv})
}

func (h *Handler) List(c *gin.Context) {
	page, perPage := pkg.ParsePagination(c)

	invitations, total, err := h.service.List(page, perPage)
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to list invitations"))
		return
	}

	pkg.Paginated(c, invitations, total, page, perPage)
}

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
	}

	settings, err := h.service.GetAllSettings()
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{"settings": settings})
}
