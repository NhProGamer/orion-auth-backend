package session

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"OrionAuth/middleware"
	"OrionAuth/pkg"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(authenticated *gin.RouterGroup) {
	authenticated.GET("/me/sessions", h.List)
	authenticated.DELETE("/me/sessions/:id", h.Revoke)
	authenticated.DELETE("/me/sessions", h.RevokeAll)
}

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

	pkg.OK(c, gin.H{"sessions": result})
}

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

	pkg.OK(c, gin.H{"message": "session revoked"})
}

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

	pkg.OK(c, gin.H{
		"message":         "sessions revoked",
		"revoked_count":   count,
	})
}
