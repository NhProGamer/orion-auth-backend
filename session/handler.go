package session

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

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

// RegisterRoutes wires the session self-service routes.
//
//	readPerm   — account:read_profile (List)
//	managePerm — account:manage_sessions (Revoke, RevokeAll)
func (h *Handler) RegisterRoutes(authenticated *gin.RouterGroup, readPerm, managePerm gin.HandlerFunc) {
	read := authenticated.Group("")
	if readPerm != nil {
		read.Use(readPerm)
	}
	read.GET("/me/sessions", h.List)

	manage := authenticated.Group("")
	if managePerm != nil {
		manage.Use(managePerm)
	}
	manage.DELETE("/me/sessions/:id", h.Revoke)
	manage.DELETE("/me/sessions", h.RevokeAll)
}

// List godoc
// @Summary      List active sessions for the current user
// @Tags         Sessions
// @Accept       json
// @Produce      json
// @Success      200  {object}  map[string]any
// @Failure      401  {object}  pkg.AppError
// @Failure      500  {object}  pkg.AppError
// @Security     BearerAuth
// @Router       /api/v1/me/sessions [get]
func (h *Handler) List(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}

	sessions, err := h.service.ListActive(userID)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	currentSessionID, _ := middleware.GetSessionID(c)

	result := make([]gin.H, 0, len(sessions))
	for _, s := range sessions {
		entry := gin.H{
			"id":               s.ID,
			"ip_address":       s.IPAddress,
			"user_agent":       s.UserAgent,
			"device_info":      s.DeviceInfo,
			"last_active_at":   s.LastActiveAt,
			"authenticated_at": s.AuthenticatedAt,
			"created_at":       s.CreatedAt,
			"current":          s.ID == currentSessionID,
		}
		result = append(result, entry)
	}

	pkg.List(c, result, len(result))
}

// Revoke godoc
// @Summary      Revoke a specific session
// @Tags         Sessions
// @Accept       json
// @Produce      json
// @Param        id   path     string  true  "Session ID (UUID)"
// @Success      200  {object}  map[string]any
// @Failure      400  {object}  pkg.AppError
// @Failure      401  {object}  pkg.AppError
// @Failure      404  {object}  pkg.AppError
// @Security     BearerAuth
// @Router       /api/v1/me/sessions/{id} [delete]
func (h *Handler) Revoke(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}

	sessionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid session ID"))
		return
	}

	if err := h.service.Revoke(sessionID, userID); err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionSessionRevoked, map[string]any{
			"session_id": sessionID,
		})
	}

	pkg.OK(c, gin.H{"message": "session revoked"})
}

// RevokeAll godoc
// @Summary      Revoke all sessions except the current one
// @Tags         Sessions
// @Accept       json
// @Produce      json
// @Success      200  {object}  map[string]any
// @Failure      401  {object}  pkg.AppError
// @Failure      500  {object}  pkg.AppError
// @Security     BearerAuth
// @Router       /api/v1/me/sessions [delete]
func (h *Handler) RevokeAll(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}

	// Keep the current session active
	currentSessionID, _ := middleware.GetSessionID(c)
	var exceptID *uuid.UUID
	if currentSessionID != uuid.Nil {
		exceptID = &currentSessionID
	}

	count, err := h.service.RevokeAll(userID, exceptID)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionSessionsRevokedAll, map[string]any{
			"revoked_count": count,
		})
	}

	pkg.OK(c, gin.H{
		"message":       "sessions revoked",
		"revoked_count": count,
	})
}
