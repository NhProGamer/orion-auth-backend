package oauth

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
	"orion-auth-backend/policy/inputs"
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
	Aud       string `json:"aud,omitempty"`
}

func (s *Service) Introspect(token, tokenTypeHint, issuer string, requestingClientID uuid.UUID) (*IntrospectResponse, error) {
	if token == "" {
		return nil, pkg.ErrInvalidRequest("missing token")
	}

	tokenHash := crypto.HashToken(token)

	// Try access token first (or if hinted)
	if tokenTypeHint == "" || tokenTypeHint == "access_token" {
		at, err := s.repo.FindAccessToken(tokenHash)
		if err == nil && at != nil {
			return s.introspectAccessToken(at, issuer, requestingClientID), nil
		}
	}

	// Try refresh token
	if tokenTypeHint == "" || tokenTypeHint == "refresh_token" {
		rt, err := s.repo.FindRefreshToken(tokenHash)
		if err == nil && rt != nil {
			return s.introspectRefreshToken(rt, issuer, requestingClientID), nil
		}
	}

	// Token not found = inactive
	return &IntrospectResponse{Active: false}, nil
}

func (s *Service) introspectAccessToken(at *model.AccessToken, issuer string, requestingClientID uuid.UUID) *IntrospectResponse {
	if !at.IsValid() {
		return &IntrospectResponse{Active: false}
	}

	if s.deniedByIntrospectPolicy("access_token", at.ClientID, at.UserID, []string(at.Scopes), at.Audience, requestingClientID) {
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

	if at.Audience != nil {
		resp.Aud = *at.Audience
	}

	if at.UserID != nil {
		resp.Sub = at.UserID.String()
		// Only return username to the client that owns the token
		if at.ClientID == requestingClientID {
			user, err := s.userService.GetByID(*at.UserID)
			if err == nil && user != nil {
				resp.Username = user.Email
			}
		}
	}

	return resp
}

// deniedByIntrospectPolicy evaluates introspect policies. A deny means the
// requesting client may not learn anything about this token — RFC 7662 says
// the response should look identical to "token unknown".
func (s *Service) deniedByIntrospectPolicy(tokenType string, tokenClientID uuid.UUID, tokenUserID *uuid.UUID, scopes []string, audience *string, requestingClientID uuid.UUID) bool {
	if s.policyEvaluator == nil {
		return false
	}
	uid := ""
	if tokenUserID != nil {
		uid = tokenUserID.String()
	}
	pInput := inputs.BuildIntrospectInput(
		tokenType,
		tokenClientID.String(),
		uid,
		scopes,
		audience,
		requestingClientID.String(),
		"",
	)
	result, pErr := s.policyEvaluator.Evaluate(context.Background(), "introspect", pInput)
	if pErr != nil {
		slog.Warn("introspect policy evaluation failed", "error", pErr)
		return false
	}
	return result != nil && result.Deny
}

func (s *Service) introspectRefreshToken(rt *model.RefreshToken, issuer string, requestingClientID uuid.UUID) *IntrospectResponse {
	if rt.Revoked || rt.WasRotated() || rt.ExpiresAt.Before(time.Now()) {
		return &IntrospectResponse{Active: false}
	}

	if s.deniedByIntrospectPolicy("refresh_token", rt.ClientID, &rt.UserID, []string(rt.Scopes), rt.Audience, requestingClientID) {
		return &IntrospectResponse{Active: false}
	}

	resp := &IntrospectResponse{
		Active:    true,
		Scope:     joinScopes(rt.Scopes),
		ClientID:  rt.ClientID.String(),
		TokenType: "refresh_token",
		Exp:       rt.ExpiresAt.Unix(),
		Iat:       rt.CreatedAt.Unix(),
		Sub:       rt.UserID.String(),
		Iss:       issuer,
	}
	if rt.Audience != nil {
		resp.Aud = *rt.Audience
	}
	return resp
}
