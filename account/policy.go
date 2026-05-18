package account

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/middleware"
	"orion-auth-backend/pkg"
	"orion-auth-backend/policy/inputs"
)

// PolicyEvaluator is implemented by policy.Service.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, policyType string, input map[string]any) (*PolicyResult, error)
}

// PolicyResult mirrors policy.EvalResult to keep account/ free of a hard
// dependency on the policy package.
type PolicyResult struct {
	Deny       bool
	DenyReason string
}

// RoleProvider returns role names and effective permission strings for a user.
type RoleProvider interface {
	GetUserRoleNames(userID uuid.UUID) ([]string, error)
	GetUserPermissions(userID uuid.UUID) ([]string, error)
}

// MFAStatusChecker reports whether a user has TOTP enrolled. Implemented by mfa.Service.
type MFAStatusChecker interface {
	HasMFA(userID uuid.UUID) (bool, error)
}

// PasskeyStatusChecker reports whether the user has a user-verified passkey.
type PasskeyStatusChecker interface {
	HasUserVerifiedPasskey(userID uuid.UUID) (bool, error)
}

// PolicyGate ties together everything needed to evaluate account_action
// policies. Construct one in main.go with all deps then call Middleware(action)
// to wire it into a specific route.
type PolicyGate struct {
	users    UserStore
	roles    RoleProvider
	mfa      MFAStatusChecker
	passkeys PasskeyStatusChecker
	policies PolicyEvaluator
}

func NewPolicyGate(users UserStore, roles RoleProvider, mfa MFAStatusChecker, passkeys PasskeyStatusChecker, policies PolicyEvaluator) *PolicyGate {
	return &PolicyGate{
		users:    users,
		roles:    roles,
		mfa:      mfa,
		passkeys: passkeys,
		policies: policies,
	}
}

// Middleware returns a Gin handler that evaluates the account_action policy
// for the named action and aborts with 403 if denied. Fail-open on internal
// errors (logged, but action proceeds) so a policy misconfig doesn't lock
// users out of their own account.
func (g *PolicyGate) Middleware(action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if g.policies == nil {
			c.Next()
			return
		}

		userID, ok := middleware.GetUserID(c)
		if !ok {
			c.Next()
			return
		}

		u, err := g.users.GetByID(userID)
		if err != nil || u == nil {
			c.Next()
			return
		}

		roles, _ := g.roles.GetUserRoleNames(userID)
		perms, _ := g.roles.GetUserPermissions(userID)

		var hasMFA, hasPasskey bool
		if g.mfa != nil {
			hasMFA, _ = g.mfa.HasMFA(userID)
		}
		if g.passkeys != nil {
			hasPasskey, _ = g.passkeys.HasUserVerifiedPasskey(userID)
		}

		ageDays := int(time.Since(u.CreatedAt).Hours() / 24)

		in := inputs.BuildAccountActionInput(u, roles, perms, action, hasMFA, hasPasskey, ageDays, c.ClientIP(), c.GetHeader("User-Agent"))
		result, err := g.policies.Evaluate(context.Background(), "account_action", in)
		if err != nil || result == nil {
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

