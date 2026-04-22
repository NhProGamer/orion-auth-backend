package policy

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"orion-auth-backend/model"
)

func newPolicy(name, policyType, rego string, priority int) model.Policy {
	return model.Policy{
		BaseModel: model.BaseModel{ID: uuid.New()},
		Name:      name,
		Type:      policyType,
		Rego:      rego,
		Active:    true,
		Priority:  priority,
	}
}

// ---------------------------------------------------------------------------
// Evaluate
// ---------------------------------------------------------------------------

func TestEvaluate_NoPolicies_FailOpen(t *testing.T) {
	eng := NewEngine()
	result, err := eng.Evaluate(context.Background(), model.PolicyTypeLogin, map[string]any{"user": "alice"})
	require.NoError(t, err)
	assert.True(t, result.Allow)
	assert.False(t, result.Deny)
	assert.Empty(t, result.DenyReason)
	assert.Nil(t, result.Modify)
}

func TestEvaluate_SingleAllow(t *testing.T) {
	eng := NewEngine()
	p := newPolicy("allow-all", model.PolicyTypeLogin, `
package orionauth.login

default allow := true
`, 10)

	require.NoError(t, eng.LoadPolicies([]model.Policy{p}))

	result, err := eng.Evaluate(context.Background(), model.PolicyTypeLogin, map[string]any{"user": "alice"})
	require.NoError(t, err)
	assert.True(t, result.Allow)
	assert.False(t, result.Deny)
}

func TestEvaluate_SingleDeny(t *testing.T) {
	eng := NewEngine()
	p := newPolicy("deny-blocked", model.PolicyTypeLogin, `
package orionauth.login

default allow := true

deny contains "user is blocked" if {
	input.blocked == true
}
`, 10)

	require.NoError(t, eng.LoadPolicies([]model.Policy{p}))

	result, err := eng.Evaluate(context.Background(), model.PolicyTypeLogin, map[string]any{"blocked": true})
	require.NoError(t, err)
	assert.True(t, result.Deny)
	assert.Equal(t, "user is blocked", result.DenyReason)
	assert.Equal(t, "deny-blocked", result.PolicyName)
}

func TestEvaluate_SingleModify(t *testing.T) {
	eng := NewEngine()
	p := newPolicy("add-claim", model.PolicyTypeTokenIssuance, `
package orionauth.token_issuance

default allow := true

modify["custom_claim"] := "injected" if {
	input.user == "alice"
}
`, 10)

	require.NoError(t, eng.LoadPolicies([]model.Policy{p}))

	result, err := eng.Evaluate(context.Background(), model.PolicyTypeTokenIssuance, map[string]any{"user": "alice"})
	require.NoError(t, err)
	assert.True(t, result.Allow)
	assert.False(t, result.Deny)
	require.NotNil(t, result.Modify)
	assert.Equal(t, "injected", result.Modify["custom_claim"])
}

func TestEvaluate_MultiplePolicies_PriorityOrder(t *testing.T) {
	// High-priority policy modifies; low-priority policy also modifies.
	// Both should be evaluated (no deny), and both modifications merged.
	eng := NewEngine()

	high := newPolicy("high-prio", model.PolicyTypeTokenIssuance, `
package orionauth.token_issuance

default allow := true

modify["from_high"] := "yes" if {
	true
}
`, 100)

	low := newPolicy("low-prio", model.PolicyTypeTokenIssuance, `
package orionauth.token_issuance

default allow := true

modify["from_low"] := "yes" if {
	true
}
`, 10)

	require.NoError(t, eng.LoadPolicies([]model.Policy{low, high}))

	result, err := eng.Evaluate(context.Background(), model.PolicyTypeTokenIssuance, map[string]any{})
	require.NoError(t, err)
	assert.True(t, result.Allow)
	require.NotNil(t, result.Modify)
	assert.Equal(t, "yes", result.Modify["from_high"])
	assert.Equal(t, "yes", result.Modify["from_low"])
}

func TestEvaluate_DenyShortCircuits(t *testing.T) {
	// High-priority policy denies; low-priority policy modifies.
	// The modification should NOT appear because deny short-circuits.
	eng := NewEngine()

	denier := newPolicy("denier", model.PolicyTypeClientAuth, `
package orionauth.client_auth

default allow := true

deny contains "access denied by high priority" if {
	true
}
`, 100)

	modifier := newPolicy("modifier", model.PolicyTypeClientAuth, `
package orionauth.client_auth

default allow := true

modify["should_not_appear"] := "nope" if {
	true
}
`, 10)

	require.NoError(t, eng.LoadPolicies([]model.Policy{modifier, denier}))

	result, err := eng.Evaluate(context.Background(), model.PolicyTypeClientAuth, map[string]any{})
	require.NoError(t, err)
	assert.True(t, result.Deny)
	assert.Equal(t, "access denied by high priority", result.DenyReason)
	assert.Equal(t, "denier", result.PolicyName)
	assert.Nil(t, result.Modify)
}

// ---------------------------------------------------------------------------
// LoadPolicies
// ---------------------------------------------------------------------------

func TestLoadPolicies_SortsByPriorityDescending(t *testing.T) {
	eng := NewEngine()

	p1 := newPolicy("low", model.PolicyTypeLogin, `
package orionauth.login
default allow := true
`, 1)

	p2 := newPolicy("high", model.PolicyTypeLogin, `
package orionauth.login
default allow := true
`, 100)

	p3 := newPolicy("mid", model.PolicyTypeLogin, `
package orionauth.login
default allow := true
`, 50)

	require.NoError(t, eng.LoadPolicies([]model.Policy{p1, p2, p3}))

	eng.mu.RLock()
	policies := eng.prepared[model.PolicyTypeLogin]
	eng.mu.RUnlock()

	require.Len(t, policies, 3)
	assert.Equal(t, 100, policies[0].priority)
	assert.Equal(t, 50, policies[1].priority)
	assert.Equal(t, 1, policies[2].priority)
}

func TestLoadPolicies_InvalidRego(t *testing.T) {
	eng := NewEngine()
	p := newPolicy("bad", model.PolicyTypeLogin, `this is not valid rego!!!`, 10)
	err := eng.LoadPolicies([]model.Policy{p})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad")
}

// ---------------------------------------------------------------------------
// LoadPolicy
// ---------------------------------------------------------------------------

func TestLoadPolicy_AddsNew(t *testing.T) {
	eng := NewEngine()

	p := newPolicy("new-policy", model.PolicyTypeAdminAPI, `
package orionauth.admin_api
default allow := true
`, 10)

	require.NoError(t, eng.LoadPolicy(p))

	eng.mu.RLock()
	policies := eng.prepared[model.PolicyTypeAdminAPI]
	eng.mu.RUnlock()

	require.Len(t, policies, 1)
	assert.Equal(t, p.ID, policies[0].id)
	assert.Equal(t, "new-policy", policies[0].name)
}

func TestLoadPolicy_ReplacesExisting(t *testing.T) {
	eng := NewEngine()

	p := newPolicy("original", model.PolicyTypeLogin, `
package orionauth.login
default allow := true
`, 10)

	require.NoError(t, eng.LoadPolicy(p))

	// Replace with updated name and priority, same ID
	updated := model.Policy{
		BaseModel: model.BaseModel{ID: p.ID},
		Name:      "updated",
		Type:      model.PolicyTypeLogin,
		Rego: `
package orionauth.login
default allow := true
`,
		Priority: 99,
		Active:   true,
	}
	require.NoError(t, eng.LoadPolicy(updated))

	eng.mu.RLock()
	policies := eng.prepared[model.PolicyTypeLogin]
	eng.mu.RUnlock()

	require.Len(t, policies, 1)
	assert.Equal(t, "updated", policies[0].name)
	assert.Equal(t, 99, policies[0].priority)
}

// ---------------------------------------------------------------------------
// RemovePolicy
// ---------------------------------------------------------------------------

func TestRemovePolicy_RemovesExisting(t *testing.T) {
	eng := NewEngine()

	p := newPolicy("to-remove", model.PolicyTypeLogin, `
package orionauth.login
default allow := true
`, 10)

	require.NoError(t, eng.LoadPolicy(p))
	eng.RemovePolicy(p.ID, model.PolicyTypeLogin)

	eng.mu.RLock()
	policies := eng.prepared[model.PolicyTypeLogin]
	eng.mu.RUnlock()

	assert.Empty(t, policies)
}

func TestRemovePolicy_NonExistent_NoOp(t *testing.T) {
	eng := NewEngine()

	p := newPolicy("keeper", model.PolicyTypeLogin, `
package orionauth.login
default allow := true
`, 10)
	require.NoError(t, eng.LoadPolicy(p))

	// Remove an ID that does not exist
	eng.RemovePolicy(uuid.New(), model.PolicyTypeLogin)

	eng.mu.RLock()
	policies := eng.prepared[model.PolicyTypeLogin]
	eng.mu.RUnlock()

	assert.Len(t, policies, 1)
}

// ---------------------------------------------------------------------------
// ValidateRego
// ---------------------------------------------------------------------------

func TestValidateRego(t *testing.T) {
	eng := NewEngine()

	t.Run("valid rego returns nil", func(t *testing.T) {
		err := eng.ValidateRego(`
package orionauth.login
default allow := true
deny contains "nope" if { input.x == 1 }
`)
		assert.NoError(t, err)
	})

	t.Run("invalid syntax returns error", func(t *testing.T) {
		err := eng.ValidateRego(`this is totally broken {{{`)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid rego")
	})
}

// ---------------------------------------------------------------------------
// EvaluateRaw
// ---------------------------------------------------------------------------

func TestEvaluateRaw(t *testing.T) {
	eng := NewEngine()
	ctx := context.Background()

	t.Run("allow result", func(t *testing.T) {
		result, err := eng.EvaluateRaw(ctx, `
package orionauth.login
default allow := true
`, map[string]any{})
		require.NoError(t, err)
		assert.True(t, result.Allow)
		assert.False(t, result.Deny)
	})

	t.Run("deny result with reason", func(t *testing.T) {
		result, err := eng.EvaluateRaw(ctx, `
package orionauth.login
default allow := true
deny contains "ip is blocked" if { input.ip == "10.0.0.1" }
`, map[string]any{"ip": "10.0.0.1"})
		require.NoError(t, err)
		assert.True(t, result.Deny)
		assert.Equal(t, "ip is blocked", result.DenyReason)
	})

	t.Run("modify result", func(t *testing.T) {
		result, err := eng.EvaluateRaw(ctx, `
package orionauth.token_issuance
default allow := true
modify["extra_scope"] := "admin" if { input.role == "superuser" }
`, map[string]any{"role": "superuser"})
		require.NoError(t, err)
		assert.True(t, result.Allow)
		require.NotNil(t, result.Modify)
		assert.Equal(t, "admin", result.Modify["extra_scope"])
	})

	t.Run("compilation error returns error", func(t *testing.T) {
		_, err := eng.EvaluateRaw(ctx, `not valid rego at all!!!`, map[string]any{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "compilation failed")
	})
}
