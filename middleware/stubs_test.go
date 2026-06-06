package middleware

import (
	"errors"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"orion-auth-backend/model"
)

// Test stubs for the three interfaces introduced in Phase 2.1. Kept in a
// shared _test.go file so every middleware test reuses the same shapes.

type stubClients struct {
	byID map[uuid.UUID]*model.OAuthClient
	err  error
}

func (s *stubClients) FindActive(id uuid.UUID) (*model.OAuthClient, error) {
	if s.err != nil {
		return nil, s.err
	}
	c, ok := s.byID[id]
	if !ok {
		return nil, nil
	}
	return c, nil
}

type stubTokens struct {
	byRaw map[string]*model.AccessToken
	err   error
}

func (s *stubTokens) LookupActiveAccessToken(raw string) (*model.AccessToken, error) {
	if s.err != nil {
		return nil, s.err
	}
	t, ok := s.byRaw[raw]
	if !ok {
		return nil, nil
	}
	return t, nil
}

type stubSessions struct {
	active map[uuid.UUID]bool
	err    error
}

func (s *stubSessions) IsActive(id uuid.UUID) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	return s.active[id], nil
}

// errBoom is a generic sentinel for "the dependency blew up" path tests.
var errBoom = errors.New("boom")

// tokenWith builds a minimal AccessToken with the given fields set. Keeps
// the test cases dense without manual struct construction.
func tokenWith(id string, clientID uuid.UUID, userID *uuid.UUID, sessionID *uuid.UUID, scopes []string, audience *string) *model.AccessToken {
	return &model.AccessToken{
		ID:        id,
		ClientID:  clientID,
		UserID:    userID,
		SessionID: sessionID,
		Scopes:    pq.StringArray(scopes),
		Audience:  audience,
	}
}
