package oauth

import (
	"context"
	"log/slog"
	"strings"

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

	// JWT access token branch: try signature verification before any DB
	// lookup. We still consult the row keyed by sha256(token) so that
	// policy denial and the legacy Revoked flag stay authoritative; the
	// JTI denylist is the secondary kill switch for tokens we never
	// persisted (e.g. an external introspect request after server
	// restart).
	if (tokenTypeHint == "" || tokenTypeHint == "access_token") && s.jwtSigner != nil && looksLikeJWT(token) {
		if claims, err := s.jwtSigner.ValidateAccessTokenJWT(token); err == nil {
			if resp := s.introspectJWTAccessToken(claims, issuer, requestingClientID); resp != nil {
				return resp, nil
			}
		}
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

// looksLikeJWT is a cheap pre-check to avoid calling the JWT verifier on
// every opaque token. JWTs have exactly two dots separating three base64url
// segments.
func looksLikeJWT(token string) bool {
	return strings.Count(token, ".") == 2
}

// introspectJWTAccessToken builds an IntrospectResponse from validated JWT
// claims, honouring the denylist and the existing introspect policy. Returns
// nil when the JWT is technically valid but should not be revealed (so the
// caller can fall through to the opaque path or final inactive response).
func (s *Service) introspectJWTAccessToken(claims map[string]any, issuer string, requestingClientID uuid.UUID) *IntrospectResponse {
	jti, _ := claims["jti"].(string)
	if jti != "" {
		if revoked, err := s.repo.IsJTIRevoked(jti); err == nil && revoked {
			return &IntrospectResponse{Active: false}
		}
	}

	clientIDStr, _ := claims["client_id"].(string)
	tokenClientID, _ := uuid.Parse(clientIDStr)

	scopeStr, _ := claims["scope"].(string)
	scopes := parseSpaceDelimited(scopeStr)

	var aud *string
	if a, ok := claims["aud"].(string); ok && a != "" {
		aud = &a
	}

	var tokenUserID *uuid.UUID
	if sub, ok := claims["sub"].(string); ok && sub != "" && sub != clientIDStr {
		if uid, err := uuid.Parse(sub); err == nil {
			tokenUserID = &uid
		}
	}

	if s.deniedByIntrospectPolicy("access_token", tokenClientID, tokenUserID, scopes, aud, requestingClientID) {
		return &IntrospectResponse{Active: false}
	}

	resp := &IntrospectResponse{
		Active:    true,
		Scope:     scopeStr,
		ClientID:  clientIDStr,
		TokenType: "Bearer",
		Iss:       issuer,
	}
	if exp, ok := claims["exp"].(float64); ok {
		resp.Exp = int64(exp)
	}
	if iat, ok := claims["iat"].(float64); ok {
		resp.Iat = int64(iat)
	}
	if aud != nil {
		resp.Aud = *aud
	}
	if sub, ok := claims["sub"].(string); ok {
		resp.Sub = sub
	}
	if tokenUserID != nil && tokenClientID == requestingClientID && s.userService != nil {
		if u, err := s.userService.GetByID(*tokenUserID); err == nil && u != nil {
			resp.Username = u.Email
		}
	}
	return resp
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
	if rt.Revoked || rt.WasRotated() || rt.ExpiresAt.Before(s.clock.Now()) {
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
