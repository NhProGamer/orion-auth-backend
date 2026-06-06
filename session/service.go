package session

import (
	"log/slog"
	"time"

	"github.com/google/uuid"

	"orion-auth-backend/config"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
	"orion-auth-backend/pkg/clock"
)

type Service struct {
	repo        RepositoryInterface
	cfg         config.AuthConfig
	ttlResolver TTLResolver
	clock       clock.Clock
}

func NewService(repo RepositoryInterface, cfg config.AuthConfig) *Service {
	return &Service{repo: repo, cfg: cfg, clock: clock.Real()}
}

// SetClock overrides the time source after construction. Tests wire a
// *clock.Fake to assert exact TTL boundaries; production never calls
// this because NewService installs clock.Real().
func (s *Service) SetClock(c clock.Clock) {
	if c != nil {
		s.clock = c
	}
}

func (s *Service) now() time.Time {
	if s.clock == nil {
		return time.Now()
	}
	return s.clock.Now()
}

// TTLResolver is the optional hook through which the service resolves the
// session TTL at creation time. When unset, the service falls back to
// cfg.SessionTTL / cfg.SessionExtendedTTL. Use SetTTLResolver to wire an
// admin-overridable resolver (see invitation.Service for the live wiring).
type TTLResolver interface {
	SessionTTL(extended bool) time.Duration
}

func (s *Service) SetTTLResolver(r TTLResolver) {
	s.ttlResolver = r
}

func (s *Service) resolveTTL(extended bool) time.Duration {
	if s.ttlResolver != nil {
		return s.ttlResolver.SessionTTL(extended)
	}
	if extended {
		return s.cfg.SessionExtendedTTL
	}
	return s.cfg.SessionTTL
}

type CreateInput struct {
	UserID    uuid.UUID
	IPAddress string
	UserAgent string
	Extended  bool
}

func (s *Service) Create(input CreateInput) (*model.Session, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, pkg.ErrInternal("failed to generate session ID")
	}

	now := s.now()
	ipAddr := &input.IPAddress
	if input.IPAddress == "" {
		ipAddr = nil
	}
	ua := &input.UserAgent
	if input.UserAgent == "" {
		ua = nil
	}

	session := &model.Session{
		ID:              id,
		UserID:          input.UserID,
		IPAddress:       ipAddr,
		UserAgent:       ua,
		LastActiveAt:    now,
		AuthenticatedAt: now,
		ExpiresAt:       now.Add(s.resolveTTL(input.Extended)),
	}

	if err := s.repo.Create(session); err != nil {
		slog.Error("failed to create session", "error", err)
		return nil, pkg.ErrInternal("failed to create session")
	}

	slog.Info("session created", "session_id", session.ID, "user_id", session.UserID)
	return session, nil
}

// IsActive returns true when the session exists, is not revoked, and has
// not yet expired. Used by middleware.BearerAuth to gate user-bound access
// tokens behind their parent session — moves the rule out of a raw SELECT
// in the middleware and into the service that owns sessions.
func (s *Service) IsActive(id uuid.UUID) (bool, error) {
	sess, err := s.repo.FindByID(id)
	if err != nil {
		return false, err
	}
	if sess == nil {
		return false, nil
	}
	return !sess.Revoked && sess.ExpiresAt.After(s.now()), nil
}

func (s *Service) ListActive(userID uuid.UUID) ([]model.Session, error) {
	sessions, err := s.repo.FindActiveByUser(userID)
	if err != nil {
		return nil, pkg.ErrInternal("failed to list sessions")
	}
	return sessions, nil
}

func (s *Service) Revoke(sessionID, userID uuid.UUID) error {
	session, err := s.repo.FindByID(sessionID)
	if err != nil {
		return pkg.ErrInternal("failed to find session")
	}
	if session == nil {
		return pkg.ErrNotFound("session not found")
	}
	if session.UserID != userID {
		return pkg.ErrForbidden("session does not belong to user")
	}
	if session.Revoked {
		return nil // already revoked, idempotent
	}

	if err := s.repo.Revoke(sessionID); err != nil {
		return pkg.ErrInternal("failed to revoke session")
	}

	slog.Info("session revoked", "session_id", sessionID, "user_id", userID)
	return nil
}

func (s *Service) RevokeAll(userID uuid.UUID, currentSessionID *uuid.UUID) (int64, error) {
	count, err := s.repo.RevokeAllForUser(userID, currentSessionID)
	if err != nil {
		return 0, pkg.ErrInternal("failed to revoke sessions")
	}

	slog.Info("sessions revoked", "user_id", userID, "count", count)
	return count, nil
}
