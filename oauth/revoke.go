package oauth

import (
	"log/slog"

	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
)

// Revoke handles token revocation per RFC 7009.
// Revoking a refresh token also revokes all associated access tokens.
func (s *Service) Revoke(token, tokenTypeHint string, client *model.OAuthClient) error {
	if token == "" {
		return pkg.ErrInvalidRequest("missing token")
	}

	tokenHash := crypto.HashToken(token)

	// Try refresh token first (higher impact, cascade revocation)
	if tokenTypeHint == "" || tokenTypeHint == "refresh_token" {
		rt, err := s.repo.FindRefreshToken(tokenHash)
		if err == nil && rt != nil {
			// Verify client ownership
			if rt.ClientID != client.ID {
				// RFC 7009: return success even if client doesn't own the token
				return nil
			}
			return s.revokeRefreshToken(rt)
		}
	}

	// Try access token
	if tokenTypeHint == "" || tokenTypeHint == "access_token" {
		at, err := s.repo.FindAccessToken(tokenHash)
		if err == nil && at != nil {
			if at.ClientID != client.ID {
				return nil
			}
			return s.revokeAccessToken(at)
		}
	}

	// Token not found: RFC 7009 says return success anyway
	return nil
}

func (s *Service) revokeRefreshToken(rt *model.RefreshToken) error {
	// Revoke the entire family (all rotated tokens)
	if err := s.repo.RevokeRefreshTokenFamily(rt.FamilyID); err != nil {
		return pkg.ErrServerError("failed to revoke refresh token")
	}

	// Cascade: revoke all access tokens for this session
	if err := s.repo.RevokeAccessTokensBySession(rt.SessionID); err != nil {
		slog.Warn("failed to cascade revoke access tokens", "session_id", rt.SessionID)
	}

	slog.Info("refresh token family revoked", "family_id", rt.FamilyID, "user_id", rt.UserID)
	return nil
}

func (s *Service) revokeAccessToken(at *model.AccessToken) error {
	if err := s.repo.RevokeAccessToken(at.ID); err != nil {
		return pkg.ErrServerError("failed to revoke access token")
	}

	slog.Info("access token revoked", "client_id", at.ClientID)
	return nil
}
