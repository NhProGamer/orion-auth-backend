package client

import (
	"errors"

	"github.com/google/uuid"

	"orion-auth-backend/model"
)

// stubClientRepo is an in-memory RepositoryInterface used by the security
// regression tests (SSRF, redirect_uri scheme). It tracks how many objects
// were persisted so the SSRF tests can verify the bad input was rejected
// BEFORE a row reached the database.
type stubClientRepo struct {
	clients map[uuid.UUID]*model.OAuthClient
	created int
}

func newStubClientRepo() *stubClientRepo {
	return &stubClientRepo{clients: map[uuid.UUID]*model.OAuthClient{}}
}

func (s *stubClientRepo) Create(c *model.OAuthClient) error {
	if c.ID == uuid.Nil {
		id, _ := uuid.NewV7()
		c.ID = id
	}
	s.clients[c.ID] = c
	s.created++
	return nil
}

func (s *stubClientRepo) FindByID(id uuid.UUID) (*model.OAuthClient, error) {
	c, ok := s.clients[id]
	if !ok {
		return nil, nil
	}
	return c, nil
}

func (s *stubClientRepo) FindActiveByID(id uuid.UUID) (*model.OAuthClient, error) {
	c, _ := s.FindByID(id)
	if c == nil || !c.Active {
		return nil, nil
	}
	return c, nil
}

func (s *stubClientRepo) Update(c *model.OAuthClient) error {
	if _, ok := s.clients[c.ID]; !ok {
		return errors.New("not found")
	}
	s.clients[c.ID] = c
	return nil
}

func (s *stubClientRepo) List(_, _ int) ([]model.OAuthClient, int64, error) {
	out := make([]model.OAuthClient, 0, len(s.clients))
	for _, c := range s.clients {
		out = append(out, *c)
	}
	return out, int64(len(out)), nil
}

func (s *stubClientRepo) Delete(id uuid.UUID) error {
	delete(s.clients, id)
	return nil
}
