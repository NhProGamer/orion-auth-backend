package federation

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"orion-auth-backend/model"
)

func TestApplyAttributeMapper_DefaultMappingExtractsStandardClaims(t *testing.T) {
	raw := map[string]any{
		"sub":            "user-123",
		"email":          "alice@example.com",
		"email_verified": true,
		"name":           "Alice Example",
		"picture":        "https://cdn.example.com/avatars/alice.png",
	}
	claims, err := applyAttributeMapper(raw, nil)
	require.NoError(t, err)
	assert.Equal(t, "user-123", claims.ExternalID)
	assert.Equal(t, "alice@example.com", claims.Email)
	assert.True(t, claims.EmailVerified)
	assert.Equal(t, "Alice Example", claims.Name)
	assert.Equal(t, "https://cdn.example.com/avatars/alice.png", claims.Picture)
}

func TestApplyAttributeMapper_OverridesPickAlternateClaims(t *testing.T) {
	raw := map[string]any{
		"id":         "gh-42",
		"login":      "alice",
		"avatar_url": "https://cdn.example.com/a.png",
	}
	mapper := json.RawMessage(`{"external_id":"id","name":"login","picture":"avatar_url"}`)
	claims, err := applyAttributeMapper(raw, mapper)
	require.NoError(t, err)
	assert.Equal(t, "gh-42", claims.ExternalID)
	assert.Equal(t, "alice", claims.Name)
	assert.Equal(t, "https://cdn.example.com/a.png", claims.Picture)
	assert.Empty(t, claims.Email, "unmapped claims must be empty, not undefined")
}

func TestApplyAttributeMapper_MissingClaimsLeaveZeroValues(t *testing.T) {
	claims, err := applyAttributeMapper(map[string]any{"sub": "abc"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "abc", claims.ExternalID)
	assert.False(t, claims.EmailVerified)
}

func TestProcessCallback_RejectsMissingState(t *testing.T) {
	svc := NewService(newMockRepo(), "https://auth.example.com", newKey(t))
	svc.SetStateRepository(newMockStateRepo())
	_, err := svc.ProcessCallback(context.Background(), "any", "some-code", "unknown-state")
	require.Error(t, err)
}

func TestProcessCallback_RejectsMissingCodeOrState(t *testing.T) {
	svc := NewService(newMockRepo(), "https://auth.example.com", newKey(t))
	svc.SetStateRepository(newMockStateRepo())
	_, err := svc.ProcessCallback(context.Background(), "any", "", "")
	require.Error(t, err)
}

func TestProcessCallback_RejectsCrossProviderState(t *testing.T) {
	repo := newMockRepo()
	state := newMockStateRepo()
	svc := NewService(repo, "https://auth.example.com", newKey(t))
	svc.SetStateRepository(state)

	id, _ := uuid.NewV7()
	other, _ := uuid.NewV7()
	// State persisted under provider A.
	_ = state.InsertAuthRequest(&model.FederationAuthRequest{
		State:      "shared-state",
		ProviderID: other, // different provider than the one we'll look up
		ExpiresAt:  time.Now().Add(time.Minute),
	})

	// But the lookup-by-name resolves to provider id (different UUID).
	iss := "https://accounts.example.com"
	_ = repo.CreateProvider(&model.FederationProvider{
		BaseModel: model.BaseModel{ID: id},
		Name:      "test-provider",
		Type:      ProviderTypeOIDC,
		ClientID:  "client",
		IssuerURL: &iss,
	})

	_, err := svc.ProcessCallback(context.Background(), "test-provider", "code", "shared-state")
	require.Error(t, err)
}
