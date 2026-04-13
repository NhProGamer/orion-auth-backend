package federation

import (
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

func (h *Handler) InitSocialLogin(c *gin.Context) {
	providerName := c.Param("provider")

	authURL, err := h.service.InitSocialLogin(providerName)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{"authorization_url": authURL})
}

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
	pkg.Created(c, gin.H{"provider": p})
}

func (h *Handler) ListProviders(c *gin.Context) {
	providers, err := h.service.ListProviders()
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to list providers"))
		return
	}
	pkg.OK(c, gin.H{"providers": providers})
}

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
	pkg.OK(c, gin.H{"provider": p})
}

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
	pkg.OK(c, gin.H{"message": "provider deleted"})
}
