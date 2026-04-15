package audit

import (
	"github.com/gin-gonic/gin"

	"orion-auth-backend/middleware"
)

// LogFromContext is a convenience method for handler-level audit logging.
// It extracts IP, UserAgent, and UserID from the gin.Context automatically.
func (s *Service) LogFromContext(c *gin.Context, action string, metadata map[string]any) {
	entry := LogEntry{
		Action:    action,
		IPAddress: c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
		Metadata:  metadata,
	}
	if userID, ok := middleware.GetUserID(c); ok {
		entry.UserID = &userID
	}
	s.Log(entry)
}
