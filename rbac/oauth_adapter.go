package rbac

import (
	"github.com/google/uuid"
)

// OAuthRoleProvider adapts rbac.Service to the oauth.RoleProvider
// interface (declared narrowly in the oauth package as the contract
// it needs to enrich policy inputs). Lives here rather than in
// oauth/ to keep the consumer free of any RBAC-side details.
//
// Wired in main.go via:
//
//	oauth.NewService(oauth.Options{
//	    RoleProvider: rbac.NewOAuthRoleProvider(rbacService),
//	    ...
//	})
type OAuthRoleProvider struct {
	svc *Service
}

func NewOAuthRoleProvider(s *Service) *OAuthRoleProvider {
	return &OAuthRoleProvider{svc: s}
}

func (a *OAuthRoleProvider) GetUserRoleNames(userID uuid.UUID) ([]string, error) {
	roles, err := a.svc.GetUserRoles(userID)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = r.Name
	}
	return names, nil
}

func (a *OAuthRoleProvider) GetUserPermissions(userID uuid.UUID) ([]string, error) {
	return a.svc.GetUserPermissions(userID)
}
