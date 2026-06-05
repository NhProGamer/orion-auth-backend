package policy

import (
	"context"

	"orion-auth-backend/account"
	"orion-auth-backend/oauth"
)

// OAuthAdapter adapts policy.Service to the oauth.PolicyEvaluator interface.
type OAuthAdapter struct {
	service *Service
}

// NewOAuthAdapter creates a new adapter for the OAuth service.
func NewOAuthAdapter(s *Service) *OAuthAdapter {
	return &OAuthAdapter{service: s}
}

// Evaluate delegates to the policy engine and returns an oauth.PolicyResult.
func (a *OAuthAdapter) Evaluate(ctx context.Context, policyType string, input map[string]any) (*oauth.PolicyResult, error) {
	result, err := a.service.Evaluate(ctx, policyType, input)
	if err != nil {
		return nil, err
	}
	return &oauth.PolicyResult{
		Allow:      result.Allow,
		Deny:       result.Deny,
		DenyReason: result.DenyReason,
		Modify:     result.Modify,
	}, nil
}

// AccountAdapter adapts policy.Service to the account.PolicyEvaluator
// interface (account only needs the deny + reason projection of the
// full policy result).
type AccountAdapter struct {
	service *Service
}

func NewAccountAdapter(s *Service) *AccountAdapter {
	return &AccountAdapter{service: s}
}

func (a *AccountAdapter) Evaluate(ctx context.Context, policyType string, input map[string]any) (*account.PolicyResult, error) {
	r, err := a.service.Evaluate(ctx, policyType, input)
	if err != nil || r == nil {
		return nil, err
	}
	return &account.PolicyResult{Deny: r.Deny, DenyReason: r.DenyReason}, nil
}

// DeciderAdapter adapts policy.Service to the middleware.PolicyEvaluator
// interface — a narrow (bool, string, error) return that the
// ClientAuth middleware consumes for policy checks during token
// endpoint client authentication.
type DeciderAdapter struct {
	service *Service
}

func NewDeciderAdapter(s *Service) *DeciderAdapter {
	return &DeciderAdapter{service: s}
}

func (a *DeciderAdapter) Evaluate(ctx context.Context, policyType string, input map[string]any) (bool, string, error) {
	r, err := a.service.Evaluate(ctx, policyType, input)
	if err != nil || r == nil {
		return false, "", err
	}
	return r.Deny, r.DenyReason, nil
}
