package federation

import (
	"github.com/google/uuid"

	"orion-auth-backend/oauth"
)

// OAuthResumerAdapter bridges federation.OAuthResumer onto the real
// oauth.Service, translating oauth.* types into federation.* types so
// the federation package stays free of leaks from the oauth domain.
// Wired in main.go via fedService.SetOAuthResumer(NewOAuthResumer(oauthService)).
//
// Lives here (not in main.go) because the contract is intrinsically
// federation's: federation declares OAuthResumer interface, and the
// translation glue belongs alongside the interface, not in the
// composition root.
type OAuthResumerAdapter struct {
	inner *oauth.Service
}

func NewOAuthResumer(s *oauth.Service) *OAuthResumerAdapter {
	return &OAuthResumerAdapter{inner: s}
}

func (a *OAuthResumerAdapter) ResumeAuthorizeAfterExternalLogin(requestID, userID uuid.UUID, providerName, ip, ua string) (*OAuthLoginStatus, error) {
	resp, err := a.inner.ResumeAuthorizeAfterExternalLogin(requestID, userID, providerName, ip, ua)
	if err != nil {
		return nil, err
	}
	return &OAuthLoginStatus{
		RequestID:       resp.RequestID,
		Authenticated:   resp.Authenticated,
		RequiresConsent: resp.RequiresConsent,
		RequiresMFA:     resp.RequiresMFA,
		Scopes:          resp.Scopes,
	}, nil
}

func (a *OAuthResumerAdapter) CompleteAuthorizeFirstParty(requestID uuid.UUID, ip, ua string) (*OAuthCompletion, error) {
	resp, err := a.inner.CompleteAuthorizeFirstParty(requestID, ip, ua)
	if err != nil {
		return nil, err
	}
	url, err := oauth.BuildAuthorizeRedirectURL(resp)
	if err != nil {
		return nil, err
	}
	return &OAuthCompletion{RedirectURL: url}, nil
}
