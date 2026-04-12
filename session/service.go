package session

import (
	"log/slog"
	"time"

	"github.com/google/uuid"

	"OrionAuth/config"
	"OrionAuth/model"
	"OrionAuth/pkg"
)

type Service struct {
	repo *Repository
	cfg  config.AuthConfig
}

func NewService(repo *Repository, cfg config.AuthConfig) *Service {
	return &Service{repo: repo, cfg: cfg}
}

type CreateInput struct {
	UserID    uuid.UUID
	IPAddress string
	UserAgent string
}

func (s *Service) Create(input CreateInput) (*model.Session, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, pkg.ErrInternal("failed to generate session ID")
	}

	now := time.Now()
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
		ExpiresAt:       now.Add(s.cfg.SessionTTL),
	}

	if err := s.repo.Create(session); err != nil {
		slog.Error("failed to create session", "error", err)
		return nil, pkg.ErrInternal("failed to create session")
	}

	slog.Info("session created", "session_id", session.ID, "user_id", session.UserID)
	return session, nil
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
