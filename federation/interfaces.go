package federation

import (
	"github.com/google/uuid"

	"orion-auth-backend/model"
	"orion-auth-backend/user"
)

type RepositoryInterface interface {
	CreateProvider(p *model.FederationProvider) error
	FindProviderByID(id uuid.UUID) (*model.FederationProvider, error)
	FindProviderByName(name string) (*model.FederationProvider, error)
	ListProviders() ([]model.FederationProvider, error)
	UpdateProvider(p *model.FederationProvider) error
	DeleteProvider(id uuid.UUID) error
	CreateLink(l *model.FederationLink) error
	FindLink(providerID uuid.UUID, externalID string) (*model.FederationLink, error)
	FindLinksByUser(userID uuid.UUID) ([]model.FederationLink, error)
	DeleteLink(id uuid.UUID) error
	FindLinkByID(id uuid.UUID) (*model.FederationLink, error)
}

// UserProvisioner is the subset of user.Service operations the federation
// flow needs to look up, create and verify accounts. Kept narrow so the
// federation package stays decoupled from the user package internals.
type UserProvisioner interface {
	FindByEmail(email string) (*model.User, error)
	GetByID(id uuid.UUID) (*model.User, error)
	CreateFromFederation(input user.FederationProvisionInput, roleIDs []uuid.UUID) (*model.User, error)
	VerifyPassword(id uuid.UUID, password string) (bool, error)
}

// RegistrationGate decides whether self-service signup is currently open,
// allowing the federation flow to auto-provision unknown emails without
// an invitation token. Implemented by invitation.Service.
type RegistrationGate interface {
	IsRegistrationEnabled() bool
}

// InvitationValidator looks up and consumes invitation tokens carried by
// the federation flow. Implemented by invitation.Service.
type InvitationValidator interface {
	ValidateToken(rawToken string) (*model.Invitation, error)
	ConsumeToken(inv *model.Invitation) error
}

// OAuthResumer continues an in-flight OrionAuth authorize request after the
// user has been authenticated via federation. Implemented by oauth.Service.
type OAuthResumer interface {
	ResumeAuthorizeAfterExternalLogin(requestID, userID uuid.UUID, providerName, ip, ua string) (*OAuthLoginStatus, error)
	CompleteAuthorizeFirstParty(requestID uuid.UUID, ip, ua string) (*OAuthCompletion, error)
}

// OAuthLoginStatus mirrors oauth.AuthorizeLoginResponse without dragging
// the oauth package into the federation interface contract.
type OAuthLoginStatus struct {
	RequestID       uuid.UUID
	Authenticated   bool
	RequiresConsent bool
	RequiresMFA     bool
	Scopes          []string
}

// OAuthCompletion is the rendered redirect target after completeAuthorize.
type OAuthCompletion struct {
	RedirectURL string
}
