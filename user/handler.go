package user

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"orion-auth-backend/middleware"
	"orion-auth-backend/pkg"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(public, authenticated *gin.RouterGroup) {
	if public != nil {
		public.POST("/auth/register", h.Register)
		public.POST("/auth/login", h.Login)
		public.POST("/auth/forgot-password", h.ForgotPassword)
		public.POST("/auth/reset-password", h.ResetPassword)
		public.POST("/auth/verify-email", h.VerifyEmail)
	}

	if authenticated != nil {
		authenticated.GET("/me", h.GetProfile)
		authenticated.PATCH("/me", h.UpdateProfile)
		authenticated.PUT("/me/password", h.ChangePassword)
	}
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

func (h *Handler) ForgotPassword(c *gin.Context) {
	var input ForgotPasswordInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	// Always return success to not leak email existence
	_ = h.service.ForgotPassword(input)
	pkg.OK(c, gin.H{"message": "if the email exists, a reset link has been sent"})
}

func (h *Handler) ResetPassword(c *gin.Context) {
	var input ResetPasswordInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	if err := h.service.ResetPassword(input); err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{"message": "password reset successfully"})
}

func (h *Handler) VerifyEmail(c *gin.Context) {
	var input VerifyEmailInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	if err := h.service.VerifyEmail(input); err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{"message": "email verified successfully"})
}
