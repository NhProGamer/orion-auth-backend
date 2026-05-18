package mfa

import (
	"github.com/gin-gonic/gin"

	"orion-auth-backend/audit"
	"orion-auth-backend/middleware"
	"orion-auth-backend/pkg"
	"orion-auth-backend/user"
)

type Handler struct {
	service      *Service
	userService  *user.Service
	auditService *audit.Service
}

func NewHandler(service *Service, userService *user.Service) *Handler {
	return &Handler{service: service, userService: userService}
}

func (h *Handler) SetAuditService(s *audit.Service) {
	h.auditService = s
}

// RegisterRoutes wires MFA self-service.
//
//	managePerm    — account:manage_mfa gate
//	requireReauth — step-up middleware applied to DELETE (disabling TOTP)
func (h *Handler) RegisterRoutes(authenticated *gin.RouterGroup, managePerm, requireReauth gin.HandlerFunc) {
	g := authenticated.Group("")
	if managePerm != nil {
		g.Use(managePerm)
	}
	g.POST("/me/mfa/totp/enroll", h.Enroll)
	g.POST("/me/mfa/totp/verify", h.Verify)
	g.POST("/me/mfa/backup-codes", h.RegenerateBackupCodes)

	sensitive := g.Group("")
	if requireReauth != nil {
		sensitive.Use(requireReauth)
	}
	sensitive.DELETE("/me/mfa/totp", h.Disable)
}

// Enroll godoc
// @Summary      Enroll in TOTP-based MFA
// @Tags         MFA
// @Accept       json
// @Produce      json
// @Success      200  {object}  map[string]any
// @Failure      401  {object}  pkg.AppError
// @Failure      409  {object}  pkg.AppError
// @Security     BearerAuth
// @Router       /api/v1/me/mfa/totp/enroll [post]
func (h *Handler) Enroll(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}

	u, err := h.userService.GetByID(userID)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	resp, err := h.service.Enroll(userID, u.Email)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{
		"secret": resp.Secret,
		"url":    resp.URL,
	})
}

// Verify godoc
// @Summary      Verify TOTP code to activate MFA
// @Tags         MFA
// @Accept       json
// @Produce      json
// @Param        body  body     mfa.VerifyInput  true  "TOTP code"
// @Success      200   {object}  map[string]any
// @Failure      400   {object}  pkg.AppError
// @Failure      401   {object}  pkg.AppError
// @Security     BearerAuth
// @Router       /api/v1/me/mfa/totp/verify [post]
func (h *Handler) Verify(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}

	var input VerifyInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	backupCodes, err := h.service.Verify(userID, input.Code)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionMFAEnrolled, nil)
	}

	pkg.OK(c, gin.H{
		"message":      "TOTP activated successfully",
		"backup_codes": backupCodes,
	})
}

type DisableInput struct {
	Code string `json:"code" binding:"required"`
}

// Disable godoc
// @Summary      Disable TOTP-based MFA
// @Tags         MFA
// @Accept       json
// @Produce      json
// @Param        body  body     mfa.DisableInput  true  "TOTP code for confirmation"
// @Success      200   {object}  map[string]any
// @Failure      400   {object}  pkg.AppError
// @Failure      401   {object}  pkg.AppError
// @Security     BearerAuth
// @Router       /api/v1/me/mfa/totp [delete]
func (h *Handler) Disable(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}

	var input DisableInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	if err := h.service.Disable(userID, input.Code); err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionMFADisabled, nil)
	}

	pkg.OK(c, gin.H{"message": "TOTP disabled"})
}

type BackupCodesInput struct {
	Code string `json:"code" binding:"required"`
}

// RegenerateBackupCodes godoc
// @Summary      Regenerate MFA backup codes
// @Tags         MFA
// @Accept       json
// @Produce      json
// @Param        body  body     mfa.BackupCodesInput  true  "TOTP code for confirmation"
// @Success      200   {object}  map[string]any
// @Failure      400   {object}  pkg.AppError
// @Failure      401   {object}  pkg.AppError
// @Security     BearerAuth
// @Router       /api/v1/me/mfa/backup-codes [post]
func (h *Handler) RegenerateBackupCodes(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}

	var input BackupCodesInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	codes, err := h.service.RegenerateBackupCodes(userID, input.Code)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{"backup_codes": codes})
}
