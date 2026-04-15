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

func (h *Handler) RegisterRoutes(authenticated *gin.RouterGroup) {
	authenticated.POST("/me/mfa/totp/enroll", h.Enroll)
	authenticated.POST("/me/mfa/totp/verify", h.Verify)
	authenticated.DELETE("/me/mfa/totp", h.Disable)
	authenticated.POST("/me/mfa/backup-codes", h.RegenerateBackupCodes)
}

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

	pkg.OK(c, gin.H{
		"message":      "TOTP activated successfully",
		"backup_codes": backupCodes,
	})
}

type DisableInput struct {
	Code string `json:"code" binding:"required"`
}

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

	pkg.OK(c, gin.H{"message": "TOTP disabled"})
}

type BackupCodesInput struct {
	Code string `json:"code" binding:"required"`
}

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
