package policy

import (
	"context"
	"log/slog"

	"github.com/gin-gonic/gin"

	"orion-auth-backend/middleware"
	"orion-auth-backend/pkg"
	"orion-auth-backend/policy/inputs"
	"orion-auth-backend/rbac"
)

// RequirePolicy returns a Gin middleware that evaluates admin_api policies.
// It runs AFTER RBAC middleware — policies can only further restrict, not
// grant access.
//
// FAIL-CLOSED on internal errors: a previous version of this middleware
// called c.Next() on any error path (missing user_id, RBAC lookup failure,
// policy evaluator failure). That was a defence-in-depth bypass: an admin
// who'd crafted a rule like "deny on weekends" would have it silently
// disabled the moment an unrelated dependency hiccupped. The admin API is
// the highest-privilege surface in the system; refuse the request when we
// can't be confident the policy was actually evaluated.
//
// Note: the no-user_id path is treated as an authentication problem (401)
// rather than a policy violation, since RBAC middleware should have run
// first and populated it.
func RequirePolicy(policySvc *Service, rbacSvc *rbac.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := middleware.GetUserID(c)
		if !ok {
			pkg.HandleError(c, pkg.ErrUnauthorized("admin policy gate requires an authenticated user"))
			c.Abort()
			return
		}

		permissions, err := rbacSvc.GetUserPermissions(userID)
		if err != nil {
			slog.Error("admin_api policy gate: rbac lookup failed", "error", err, "user_id", userID, "path", c.Request.URL.Path)
			pkg.HandleError(c, pkg.ErrInternal("authorization check unavailable"))
			c.Abort()
			return
		}

		input := inputs.BuildAdminAPIInput(userID, permissions, c.Request.Method, c.Request.URL.Path, c.ClientIP())
		result, err := policySvc.Evaluate(context.Background(), "admin_api", input)
		if err != nil {
			slog.Error("admin_api policy evaluation failed", "error", err, "user_id", userID, "path", c.Request.URL.Path)
			pkg.HandleError(c, pkg.ErrInternal("authorization policy unavailable"))
			c.Abort()
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
