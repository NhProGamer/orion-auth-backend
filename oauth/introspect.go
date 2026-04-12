package oauth

import (
	"time"

	"OrionAuth/crypto"
	"OrionAuth/model"
	"OrionAuth/pkg"
)

// IntrospectResponse represents the RFC 7662 introspection response.
type IntrospectResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Iss       string `json:"iss,omitempty"`
}

func (s *Service) Introspect(token, tokenTypeHint, issuer string) (*IntrospectResponse, error) {
	if token == "" {
		return nil, pkg.ErrInvalidRequest("missing token")
	}

	tokenHash := crypto.HashToken(token)

	// Try access token first (or if hinted)
	if tokenTypeHint == "" || tokenTypeHint == "access_token" {
		at, err := s.repo.FindAccessToken(tokenHash)
		if err == nil && at != nil {
			return s.introspectAccessToken(at, issuer), nil
		}
	}

	// Try refresh token
	if tokenTypeHint == "" || tokenTypeHint == "refresh_token" {
		rt, err := s.repo.FindRefreshToken(tokenHash)
		if err == nil && rt != nil {
			return s.introspectRefreshToken(rt, issuer), nil
		}
	}

	// Token not found = inactive
	return &IntrospectResponse{Active: false}, nil
}

func (s *Service) introspectAccessToken(at *model.AccessToken, issuer string) *IntrospectResponse {
	if !at.IsValid() {
		return &IntrospectResponse{Active: false}
	}

	resp := &IntrospectResponse{
		Active:    true,
		Scope:     joinScopes(at.Scopes),
		ClientID:  at.ClientID.String(),
		TokenType: "Bearer",
		Exp:       at.ExpiresAt.Unix(),
		Iat:       at.CreatedAt.Unix(),
		Iss:       issuer,
	}

	if at.UserID != nil {
		resp.Sub = at.UserID.String()
		// Look up user email for username
		user, err := s.userService.GetByID(*at.UserID)
		if err == nil && user != nil {
			resp.Username = user.Email
		}
	}

	return resp
}

func (s *Service) introspectRefreshToken(rt *model.RefreshToken, issuer string) *IntrospectResponse {
	if rt.Revoked || rt.WasRotated() || rt.ExpiresAt.Before(time.Now()) {
		return &IntrospectResponse{Active: false}
	}

	return &IntrospectResponse{
		Active:    true,
		Scope:     joinScopes(rt.Scopes),
		ClientID:  rt.ClientID.String(),
		TokenType: "refresh_token",
		Exp:       rt.ExpiresAt.Unix(),
		Iat:       rt.CreatedAt.Unix(),
		Sub:       rt.UserID.String(),
		Iss:       issuer,
	}
}
