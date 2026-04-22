package policy

import (
	"context"

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
