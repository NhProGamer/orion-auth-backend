package rbac

import (
	"github.com/gin-gonic/gin"

	"OrionAuth/middleware"
	"OrionAuth/pkg"
)

// RequirePermission returns a Gin middleware that checks if the user has the given permission.
func RequirePermission(svc *Service, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := middleware.GetUserID(c)
		if !ok {
			pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
			c.Abort()
			return
		}

		has, err := svc.HasPermission(userID, permission)
		if err != nil || !has {
			pkg.HandleError(c, pkg.ErrForbidden("insufficient permissions"))
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyPermission returns a middleware that checks if the user has any of the given permissions.
func RequireAnyPermission(svc *Service, permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := middleware.GetUserID(c)
		if !ok {
			pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
			c.Abort()
			return
		}

		for _, perm := range permissions {
			has, err := svc.HasPermission(userID, perm)
			if err == nil && has {
				c.Next()
				return
			}
		}

		pkg.HandleError(c, pkg.ErrForbidden("insufficient permissions"))
		c.Abort()
	}
}
