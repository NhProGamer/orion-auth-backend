package policy

import (
	"context"

	"github.com/gin-gonic/gin"

	"orion-auth-backend/middleware"
	"orion-auth-backend/pkg"
	"orion-auth-backend/rbac"
)

// RequirePolicy returns a Gin middleware that evaluates admin_api policies.
// It runs AFTER RBAC middleware — policies can only further restrict, not grant access.
func RequirePolicy(policySvc *Service, rbacSvc *rbac.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := middleware.GetUserID(c)
		if !ok {
			c.Next()
			return
		}

		permissions, err := rbacSvc.GetUserPermissions(userID)
		if err != nil {
			c.Next()
			return
		}

		input := BuildAdminAPIInput(userID, permissions, c.Request.Method, c.Request.URL.Path, c.ClientIP())
		result, err := policySvc.Evaluate(context.Background(), "admin_api", input)
		if err != nil {
			c.Next()
			return
		}

		if result.Deny {
			pkg.HandleError(c, pkg.ErrForbidden(result.DenyReason))
			c.Abort()
			return
		}

		c.Next()
	}
}
