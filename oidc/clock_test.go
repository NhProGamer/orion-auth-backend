package oidc

import (
	"testing"
	"time"

	"orion-auth-backend/model"
	"orion-auth-backend/pkg/clock"
)

// stubKeyRepo captures DeactivateActive's grace period so the test can
// assert it was computed from the injected clock, not wall time.
type stubKeyRepo struct {
	deactivateGrace time.Time
	createdKey      *model.SigningKey
}

func (s *stubKeyRepo) FindActive() (*model.SigningKey, error) { return nil, nil }
func (s *stubKeyRepo) FindAllValid(_ time.Time) ([]model.SigningKey, error) {
	return nil, nil
}
func (s *stubKeyRepo) DeactivateActive(grace time.Time) error {
	s.deactivateGrace = grace
	return nil
}
func (s *stubKeyRepo) Create(key *model.SigningKey) error {
	s.createdKey = key
	return nil
}

// TestRotateKey_UsesInjectedClock pins the contract that key rotation's
// 24h grace period is computed from the injected clock — the prior
// behaviour read wall time and was not testable without time.Sleep.
func TestRotateKey_UsesInjectedClock(t *testing.T) {
	t0 := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	fake := clock.NewFake(t0)
	repo := &stubKeyRepo{}

	svc := &Service{keyRepo: repo, clock: fake}

	if err := svc.RotateKey(); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	wantGrace := t0.Add(24 * time.Hour)
	if !repo.deactivateGrace.Equal(wantGrace) {
		t.Errorf("grace = %v, want %v", repo.deactivateGrace, wantGrace)
	}
	if repo.createdKey == nil {
		t.Fatal("expected a new key to be created")
	}
}
