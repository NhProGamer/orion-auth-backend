package reauth

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
)

// Method values stored in ReauthToken.Method.
const (
	MethodPassword   = "password"
	MethodTOTP       = "totp"
	MethodBackupCode = "backup_code"
	MethodPasskey    = "passkey"
)

type Service struct {
	repo         RepositoryInterface
	passwordVer  PasswordVerifier
	mfaValidator MFAValidator
	passkeyVer   PasskeyValidator
	tokenTTL     time.Duration
}

func NewService(repo RepositoryInterface, pwd PasswordVerifier, ttl time.Duration) *Service {
	return &Service{
		repo:        repo,
		passwordVer: pwd,
		tokenTTL:    ttl,
	}
}

// SetMFAValidator wires in the MFA validator after construction to avoid
// circular dependencies in main.go.
func (s *Service) SetMFAValidator(v MFAValidator) {
	s.mfaValidator = v
}

// SetPasskeyValidator wires in the passkey validator after construction.
func (s *Service) SetPasskeyValidator(v PasskeyValidator) {
	s.passkeyVer = v
}

// IssueRequest is the input for POST /me/reauth.
type IssueRequest struct {
	Method             string    `json:"method" binding:"required"`
	Password           string    `json:"password,omitempty"`
	Code               string    `json:"code,omitempty"` // TOTP or backup code
	PasskeyChallengeID uuid.UUID `json:"passkey_challenge_id,omitempty"`
	PasskeyResponse    []byte    `json:"passkey_response,omitempty"` // raw assertion JSON
}

// IssueResponse is returned by POST /me/reauth on success.
type IssueResponse struct {
	Token     string    `json:"reauth_token"`
	ExpiresAt time.Time `json:"expires_at"`
	Method    string    `json:"method"`
}

// Issue validates the requested method against the user's credentials and
// returns a fresh single-use reauth token bound to the session.
func (s *Service) Issue(userID, sessionID uuid.UUID, req IssueRequest) (*IssueResponse, error) {
	if err := s.verifyMethod(userID, req); err != nil {
		return nil, err
	}

	raw, hash, err := crypto.GenerateOpaqueToken()
	if err != nil {
		return nil, pkg.ErrInternal("failed to generate reauth token")
	}

	expiresAt := time.Now().Add(s.tokenTTL)
	token := &model.ReauthToken{
		ID:        hash,
		UserID:    userID,
		SessionID: sessionID,
		Method:    req.Method,
		ExpiresAt: expiresAt,
	}
	if err := s.repo.Create(token); err != nil {
		slog.Error("failed to persist reauth token", "error", err)
		return nil, pkg.ErrInternal("failed to issue reauth token")
	}

	slog.Info("reauth token issued", "user_id", userID, "session_id", sessionID, "method", req.Method)
	return &IssueResponse{
		Token:     raw,
		ExpiresAt: expiresAt,
		Method:    req.Method,
	}, nil
}

// Verify resolves a raw token to a valid (unused, unexpired, matching session)
// ReauthToken. Returns nil if the token is missing/invalid/expired.
func (s *Service) Verify(rawToken string, userID, sessionID uuid.UUID) (*model.ReauthToken, error) {
	if rawToken == "" {
		return nil, nil
	}
	hash := crypto.HashToken(rawToken)
	t, err := s.repo.FindByHash(hash)
	if err != nil || t == nil {
		return nil, err
	}
	if !t.IsValid() {
		return nil, nil
	}
	if t.UserID != userID || t.SessionID != sessionID {
		return nil, nil
	}
	return t, nil
}

// Consume marks a reauth token as used. Call this exactly once per sensitive
// action after Verify returned a valid token.
func (s *Service) Consume(hash, consumedBy string) error {
	if err := s.repo.MarkUsed(hash, consumedBy); err != nil {
		return pkg.ErrInternal("failed to consume reauth token")
	}
	return nil
}

// RevokeForSession deletes every reauth token bound to a revoked session so
// hijacking a token after logout is impossible.
func (s *Service) RevokeForSession(sessionID uuid.UUID) error {
	return s.repo.DeleteForSession(sessionID)
}

// CleanupExpired purges expired tokens. Called periodically by the cleanup job.
func (s *Service) CleanupExpired() (int64, error) {
	return s.repo.DeleteExpired()
}

func (s *Service) verifyMethod(userID uuid.UUID, req IssueRequest) error {
	switch req.Method {
	case MethodPassword:
		if req.Password == "" {
			return pkg.ErrBadRequest("password is required")
		}
		ok, err := s.passwordVer.VerifyPassword(userID, req.Password)
		if err != nil {
			return pkg.ErrInternal("failed to verify password")
		}
		if !ok {
			return pkg.ErrUnauthorized("invalid password")
		}
	case MethodTOTP, MethodBackupCode:
		if s.mfaValidator == nil {
			return pkg.ErrInternal("mfa validator not configured")
		}
		if req.Code == "" {
			return pkg.ErrBadRequest("code is required")
		}
		hasMFA, err := s.mfaValidator.HasMFA(userID)
		if err != nil {
			return pkg.ErrInternal("failed to check mfa")
		}
		if !hasMFA {
			return pkg.ErrBadRequest("mfa is not enrolled")
		}
		ok, err := s.mfaValidator.ValidateCode(userID, req.Code)
		if err != nil {
			return pkg.ErrInternal("failed to validate mfa code")
		}
		if !ok {
			return pkg.ErrUnauthorized("invalid mfa code")
		}
	case MethodPasskey:
		if s.passkeyVer == nil {
			return pkg.ErrInternal("passkey validator not configured")
		}
		if req.PasskeyChallengeID == uuid.Nil || len(req.PasskeyResponse) == 0 {
			return pkg.ErrBadRequest("passkey_challenge_id and passkey_response are required")
		}
		ok, err := s.passkeyVer.ValidateReauthAssertion(userID, req.PasskeyChallengeID, req.PasskeyResponse)
		if err != nil {
			return pkg.ErrInternal("failed to validate passkey assertion")
		}
		if !ok {
			return pkg.ErrUnauthorized("invalid passkey assertion")
		}
	default:
		return pkg.ErrBadRequest(fmt.Sprintf("unsupported reauth method: %s", req.Method))
	}
	return nil
}
