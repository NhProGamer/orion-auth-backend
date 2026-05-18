package inputs

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"orion-auth-backend/model"
)

func TestBuildAccountActionInput_Shape(t *testing.T) {
	u := &model.User{
		BaseModel:     model.BaseModel{ID: uuid.New()},
		Email:         "alice@example.com",
		EmailVerified: true,
		Active:        true,
	}

	in := BuildAccountActionInput(
		u,
		[]string{"user"},
		[]string{"account:update_profile"},
		"change_email",
		true,  // hasMFA
		false, // hasPasskey
		42,
		"203.0.113.5",
		"curl/8",
	)

	user, ok := in["user"].(map[string]any)
	require.True(t, ok, "user must be a map")
	assert.Equal(t, u.ID.String(), user["id"])
	assert.Equal(t, "alice@example.com", user["email"])
	assert.Equal(t, []string{"user"}, user["roles"])
	assert.Equal(t, []string{"account:update_profile"}, user["permissions"])

	assert.Equal(t, "change_email", in["action"])
	assert.Equal(t, true, in["has_mfa"])
	assert.Equal(t, false, in["has_passkey"])
	assert.Equal(t, 42, in["account_age_days"])
	assert.Equal(t, "203.0.113.5", in["ip_address"])
	assert.Equal(t, "curl/8", in["user_agent"])

	tm, ok := in["time"].(map[string]any)
	require.True(t, ok, "time must be present")
	assert.Contains(t, tm, "hour")
	assert.Contains(t, tm, "weekday")
	assert.Contains(t, tm, "weekday_n")
	assert.Contains(t, tm, "unix")
}

func TestBuildAccountActionInput_NilRolesPermissions(t *testing.T) {
	u := &model.User{
		BaseModel: model.BaseModel{ID: uuid.New()},
		Email:     "bob@example.com",
	}

	in := BuildAccountActionInput(u, nil, nil, "delete_account", false, false, 1, "", "")

	user := in["user"].(map[string]any)
	// Nil slices must be materialised as empty arrays so OPA rules like
	// `not "admin" in input.user.roles` behave the same with no roles.
	assert.NotNil(t, user["roles"])
	assert.NotNil(t, user["permissions"])
	assert.Len(t, user["roles"].([]string), 0)
	assert.Len(t, user["permissions"].([]string), 0)
}
