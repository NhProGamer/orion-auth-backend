package audit

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"OrionAuth/pkg"
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
