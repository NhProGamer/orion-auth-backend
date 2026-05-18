package audit

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/pkg"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(admin *gin.RouterGroup) {
	admin.GET("/audit-logs", h.Query)
}

// Query returns paginated audit logs with optional filters.
// @Summary Query audit logs
// @Tags Admin - Audit
// @Produce json
// @Security BearerAuth
// @Param user_id query string false "Filter by user ID"
// @Param action query string false "Filter by action"
// @Param from query string false "Start time (RFC3339)"
// @Param to query string false "End time (RFC3339)"
// @Param page query int false "Page number"
// @Param per_page query int false "Items per page"
// @Success 200 {object} pkg.PaginatedResponse
// @Failure 401 {object} map[string]any
// @Failure 500 {object} map[string]any
// @Router /api/v1/admin/audit-logs [get]
func (h *Handler) Query(c *gin.Context) {
	page, perPage := pkg.ParsePagination(c)

	input := QueryInput{
		Page:    page,
		PerPage: perPage,
	}

	if userIDStr := c.Query("user_id"); userIDStr != "" {
		uid, err := uuid.Parse(userIDStr)
		if err == nil {
			input.UserID = &uid
		}
	}

	input.Action = c.Query("action")
	input.ActionPrefix = c.Query("action_prefix")

	if fromStr := c.Query("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			input.From = &t
		}
	}
	if toStr := c.Query("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			input.To = &t
		}
	}

	logs, total, err := h.service.Query(input)
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to query audit logs"))
		return
	}

	pkg.Paginated(c, logs, total, page, perPage)
}
