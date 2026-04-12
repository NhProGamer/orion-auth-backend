package user

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"OrionAuth/middleware"
	"OrionAuth/pkg"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(public, authenticated *gin.RouterGroup) {
	public.POST("/auth/register", h.Register)
	public.POST("/auth/login", h.Login)

	authenticated.GET("/me", h.GetProfile)
	authenticated.PATCH("/me", h.UpdateProfile)
	authenticated.PUT("/me/password", h.ChangePassword)
}

func (h *Handler) Register(c *gin.Context) {
	var input RegisterInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	user, err := h.service.Register(input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"user": user.PublicProfile(),
	})
}

func (h *Handler) Login(c *gin.Context) {
	var input LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	user, err := h.service.Authenticate(input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	// Session creation is handled by the session package.
	// The handler returns the user; the caller (main router) can wrap this
	// with session creation logic.
	c.JSON(http.StatusOK, gin.H{
		"user": user.PublicProfile(),
	})
}

func (h *Handler) GetProfile(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}

	user, err := h.service.GetByID(userID)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{"user": user.PublicProfile()})
}

func (h *Handler) UpdateProfile(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}

	var input UpdateProfileInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	user, err := h.service.UpdateProfile(userID, input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{"user": user.PublicProfile()})
}

func (h *Handler) ChangePassword(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}

	var input ChangePasswordInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	if err := h.service.ChangePassword(userID, input); err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{"message": "password changed successfully"})
}
