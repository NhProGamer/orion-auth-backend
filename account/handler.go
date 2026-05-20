package account

import (
	"github.com/gin-gonic/gin"

	"orion-auth-backend/audit"
	"orion-auth-backend/middleware"
	"orion-auth-backend/pkg"
	"orion-auth-backend/user"
)

type Handler struct {
	service      *Service
	auditService *audit.Service
	reauthSvc    middleware.ReauthVerifier
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) SetAuditService(s *audit.Service) {
	h.auditService = s
}

func (h *Handler) SetReauthService(v middleware.ReauthVerifier) {
	h.reauthSvc = v
}

// RegisterRoutes wires the account self-service endpoints.
//
//	public         — POST /me/account/cancel-deletion (token-based, no bearer)
//	authenticated  — bearer auth applied; per-route permission/step-up middlewares
//	                 passed in by main.go.
func (h *Handler) RegisterRoutes(
	public *gin.RouterGroup,
	authenticated *gin.RouterGroup,
	changePasswordPerm gin.HandlerFunc,
	changeEmailPerm gin.HandlerFunc,
	deleteAccountPerm gin.HandlerFunc,
	requireReauth gin.HandlerFunc,
) {
	if public != nil {
		public.POST("/me/account/cancel-deletion", h.CancelDeletion)
		// Email confirmation also lives here as it's token-based (no bearer).
		public.POST("/me/account/email/confirm", h.ConfirmEmailChange)
	}

	if authenticated != nil {
		pwd := authenticated.Group("")
		if changePasswordPerm != nil {
			pwd.Use(changePasswordPerm)
		}
		if requireReauth != nil {
			pwd.Use(requireReauth)
		}
		pwd.PUT("/me/password", h.ChangePassword)

		// SetInitialPassword has no step-up requirement: the user has just
		// authenticated via the federation provider and has no other
		// reauth method until the password is set.
		setPwd := authenticated.Group("")
		if changePasswordPerm != nil {
			setPwd.Use(changePasswordPerm)
		}
		setPwd.POST("/me/set-password", h.SetInitialPassword)

		email := authenticated.Group("")
		if changeEmailPerm != nil {
			email.Use(changeEmailPerm)
		}
		if requireReauth != nil {
			email.Use(requireReauth)
		}
		email.POST("/me/account/email/change-request", h.RequestEmailChange)

		del := authenticated.Group("")
		if deleteAccountPerm != nil {
			del.Use(deleteAccountPerm)
		}
		if requireReauth != nil {
			del.Use(requireReauth)
		}
		del.DELETE("/me", h.RequestDeletion)
	}
}

// ChangePassword godoc
// @Summary  Change own password (step-up required)
// @Tags     Account
// @Accept   json
// @Produce  json
// @Param    body body user.ChangePasswordInput true "current + new password"
// @Success  200 {object} map[string]any
// @Security BearerAuth
// @Router   /api/v1/me/password [put]
func (h *Handler) ChangePassword(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}
	var input user.ChangePasswordInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	if err := h.service.ChangePassword(userID, input); err != nil {
		pkg.HandleError(c, err)
		return
	}
	h.consumeReauth(c, audit.ActionAccountPasswordChanged)
	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionAccountPasswordChanged, nil)
	}
	pkg.OK(c, gin.H{"message": "password changed"})
}

// SetInitialPasswordInput is the body of POST /me/set-password.
type SetInitialPasswordInput struct {
	Password string `json:"password" binding:"required"`
}

// SetInitialPassword godoc
// @Summary  Finalise federation onboarding by setting the initial local password
// @Tags     Account
// @Accept   json
// @Produce  json
// @Param    body body account.SetInitialPasswordInput true "new password"
// @Success  200 {object} map[string]any
// @Failure  400 {object} map[string]any
// @Security BearerAuth
// @Router   /api/v1/me/set-password [post]
func (h *Handler) SetInitialPassword(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}
	var input SetInitialPasswordInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	if err := h.service.SetInitialPassword(userID, input.Password); err != nil {
		pkg.HandleError(c, err)
		return
	}
	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionAccountPasswordChanged, map[string]any{"initial": true})
	}
	pkg.OK(c, gin.H{"message": "password set"})
}

// RequestEmailChange godoc
// @Summary  Request an email address change (step-up required)
// @Tags     Account
// @Accept   json
// @Produce  json
// @Param    body body account.ChangeEmailRequestInput true "new email"
// @Success  200 {object} map[string]any
// @Security BearerAuth
// @Router   /api/v1/me/account/email/change-request [post]
func (h *Handler) RequestEmailChange(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}
	var input ChangeEmailRequestInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	if err := h.service.RequestEmailChange(userID, input); err != nil {
		pkg.HandleError(c, err)
		return
	}
	h.consumeReauth(c, audit.ActionAccountEmailChangeRequested)
	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionAccountEmailChangeRequested, map[string]any{
			"new_email": input.NewEmail,
		})
	}
	pkg.OK(c, gin.H{"message": "confirmation email sent"})
}

// ConfirmEmailChange godoc
// @Summary  Confirm a pending email change with the token from the email
// @Tags     Account
// @Accept   json
// @Produce  json
// @Param    body body account.ConfirmEmailChangeInput true "token"
// @Success  200 {object} map[string]any
// @Router   /api/v1/me/account/email/confirm [post]
func (h *Handler) ConfirmEmailChange(c *gin.Context) {
	var input ConfirmEmailChangeInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	oldEmail, newEmail, userID, err := h.service.ConfirmEmailChange(input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	if h.auditService != nil {
		h.auditService.Log(audit.LogEntry{
			Action:    audit.ActionAccountEmailChanged,
			UserID:    &userID,
			IPAddress: c.ClientIP(),
			UserAgent: c.GetHeader("User-Agent"),
			Metadata: map[string]any{
				"old_email": oldEmail,
				"new_email": newEmail,
			},
		})
	}
	pkg.OK(c, gin.H{"message": "email updated"})
}

// RequestDeletion godoc
// @Summary  Schedule own account deletion with grace period (step-up required)
// @Tags     Account
// @Produce  json
// @Success  200 {object} map[string]any
// @Security BearerAuth
// @Router   /api/v1/me [delete]
func (h *Handler) RequestDeletion(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}
	if err := h.service.RequestDeletion(userID); err != nil {
		pkg.HandleError(c, err)
		return
	}
	h.consumeReauth(c, audit.ActionAccountDeletionRequested)
	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionAccountDeletionRequested, nil)
	}
	pkg.OK(c, gin.H{"message": "account scheduled for deletion"})
}

// CancelDeletion godoc
// @Summary  Cancel a pending account deletion using the emailed token
// @Tags     Account
// @Accept   json
// @Produce  json
// @Param    body body account.CancelDeletionInput true "token"
// @Success  200 {object} map[string]any
// @Router   /api/v1/me/account/cancel-deletion [post]
func (h *Handler) CancelDeletion(c *gin.Context) {
	var input CancelDeletionInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	if err := h.service.CancelDeletion(input); err != nil {
		pkg.HandleError(c, err)
		return
	}
	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionAccountDeletionCancelled, nil)
	}
	pkg.OK(c, gin.H{"message": "deletion cancelled"})
}

func (h *Handler) consumeReauth(c *gin.Context, action string) {
	if h.reauthSvc == nil {
		return
	}
	middleware.ConsumeReauth(c, h.reauthSvc, action)
}
