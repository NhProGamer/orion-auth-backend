package federation

import (
	"orion-auth-backend/invitation"
)

// InvitationLister adapts federation.Service to the
// invitation.FederationLister interface, translating
// federation.Provider into invitation.FederationProviderInfo so the
// invitation package does not need to know about federation's full
// provider model.
//
// Wired in main.go via invHandler.SetFederationLister(...).
type InvitationLister struct {
	svc *Service
}

func NewInvitationLister(s *Service) *InvitationLister {
	return &InvitationLister{svc: s}
}

func (a *InvitationLister) ListActiveProviders() ([]invitation.FederationProviderInfo, error) {
	providers, err := a.svc.ListActiveProviders()
	if err != nil {
		return nil, err
	}
	result := make([]invitation.FederationProviderInfo, len(providers))
	for i, p := range providers {
		result[i] = invitation.FederationProviderInfo{
			Name:        p.Name,
			DisplayName: p.DisplayName,
			Type:        p.Type,
		}
	}
	return result, nil
}
