package reauth

import (
	"github.com/gin-gonic/gin"

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

func (h *Handler) RegisterRoutes(authenticated *gin.RouterGroup) {
	authenticated.POST("/me/reauth", h.Issue)
}

// Issue godoc
// @Summary      Issue a short-lived step-up reauthentication token
// @Description  Validates a fresh credential (password, TOTP, backup code, or passkey assertion) and returns a single-use reauth token to use as X-Reauth-Token on sensitive endpoints.
// @Tags         Account
// @Accept       json
// @Produce      json
// @Param        body  body     reauth.IssueRequest  true  "Credential payload"
// @Success      200   {object}  reauth.IssueResponse
// @Failure      400   {object}  pkg.AppError
// @Failure      401   {object}  pkg.AppError
// @Security     BearerAuth
// @Router       /api/v1/me/reauth [post]
func (h *Handler) Issue(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}
	sessionID, ok := middleware.GetSessionID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("reauth requires a session-bound token"))
		return
	}

	var req IssueRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	resp, err := h.service.Issue(userID, sessionID, req)
	if err != nil {
		if h.auditService != nil {
			h.auditService.LogFromContext(c, audit.ActionAccountReauthFailed, map[string]any{
				"method": req.Method,
			})
		}
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionAccountReauthIssued, map[string]any{
			"method": resp.Method,
		})
	}

	pkg.OK(c, resp)
}
