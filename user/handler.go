package user

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/audit"
	"orion-auth-backend/middleware"
	"orion-auth-backend/pkg"
)

type RegistrationChecker interface {
	IsRegistrationEnabled() bool
}

type Handler struct {
	service      *Service
	regChecker   RegistrationChecker
	auditService *audit.Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) SetRegistrationChecker(checker RegistrationChecker) {
	h.regChecker = checker
}

func (h *Handler) SetAuditService(s *audit.Service) {
	h.auditService = s
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

func (h *Handler) RegisterAdminRoutes(admin *gin.RouterGroup) {
	admin.GET("/users", h.AdminListUsers)
	admin.GET("/users/:id", h.AdminGetUser)
	admin.PATCH("/users/:id", h.AdminUpdateUser)
	admin.DELETE("/users/:id", h.AdminDeleteUser)
}

func (h *Handler) AdminListUsers(c *gin.Context) {
	page, perPage := pkg.ParsePagination(c)

	users, total, err := h.service.List(page, perPage)
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to list users"))
		return
	}

	profiles := make([]map[string]any, len(users))
	for i := range users {
		profiles[i] = users[i].PublicProfile()
	}

	pkg.Paginated(c, profiles, total, page, perPage)
}

func (h *Handler) AdminGetUser(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid user ID"))
		return
	}

	user, err := h.service.GetByID(id)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{"user": user.AdminView()})
}

func (h *Handler) AdminUpdateUser(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid user ID"))
		return
	}

	var input AdminUpdateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	user, err := h.service.AdminUpdate(id, input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionUserUpdated, map[string]any{
			"target_user_id": id,
		})
	}

	pkg.OK(c, gin.H{"user": user.AdminView()})
}

func (h *Handler) AdminDeleteUser(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid user ID"))
		return
	}

	if err := h.service.Delete(id); err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionUserDeleted, map[string]any{
			"target_user_id": id,
		})
	}

	pkg.OK(c, gin.H{"message": "user deleted"})
}

func (h *Handler) Register(c *gin.Context) {
	if h.regChecker != nil && !h.regChecker.IsRegistrationEnabled() {
		pkg.HandleError(c, pkg.ErrForbidden("public registration is disabled"))
		return
	}

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

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionUserRegistered, map[string]any{
			"user_id": user.ID,
			"email":   user.Email,
		})
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
		if h.auditService != nil {
			h.auditService.LogFromContext(c, audit.ActionUserLoginFailed, map[string]any{
				"email": input.Email,
			})
		}
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionUserLogin, map[string]any{
			"user_id": user.ID,
			"email":   user.Email,
		})
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

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionPasswordChanged, nil)
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

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionPasswordReset, nil)
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

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionEmailVerified, nil)
	}

	pkg.OK(c, gin.H{"message": "email verified successfully"})
}
