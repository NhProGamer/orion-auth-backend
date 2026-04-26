package testutil

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"orion-auth-backend/config"
	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
)

// TestAuthConfig returns an AuthConfig with sensible test defaults.
func TestAuthConfig() config.AuthConfig {
	return config.AuthConfig{
		AccessTokenTTL:  1 * time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		SessionTTL:      720 * time.Hour,
		AuthCodeTTL:     10 * time.Minute,
		DeviceCodeTTL:   15 * time.Minute,
		PasswordMinLen:  8,
		MaxFailAttempts: 5,
		LockoutDuration: 15 * time.Minute,
	}
}

// FastHasher returns an Argon2Hasher with minimal params for fast tests.
func FastHasher() *crypto.Argon2Hasher {
	return crypto.NewArgon2Hasher(config.Argon2Config{
		Memory:      1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  8,
		KeyLength:   16,
	})
}

// TestClient returns a default confidential OAuth client for testing.
func TestClient() *model.OAuthClient {
	id, _ := uuid.NewV7()
	return &model.OAuthClient{
		BaseModel:       model.BaseModel{ID: id, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		Name:            "test-client",
		RedirectURIs:    pq.StringArray{"https://example.com/callback"},
		GrantTypes:      pq.StringArray{"authorization_code", "refresh_token", "client_credentials"},
		ResponseTypes:   pq.StringArray{"code"},
		Scopes:          pq.StringArray{"openid", "profile", "email", "offline_access"},
		TokenAuthMethod: "client_secret_basic",
		IsPublic:        false,
		IsFirstParty:    false,
		RequirePKCE:     true,
		AccessTokenTTL:  3600,
		RefreshTokenTTL: 86400,
		IDTokenTTL:      3600,
		Active:          true,
	}
}

// TestUser returns a user with a pre-hashed password for testing.
func TestUser(hasher *crypto.Argon2Hasher, password string) *model.User {
	id, _ := uuid.NewV7()
	hash, _ := hasher.Hash(password)
	name := "Test User"
	return &model.User{
		BaseModel:    model.BaseModel{ID: id, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		Email:        "test@example.com",
		PasswordHash: hash,
		DisplayName:  &name,
		Active:       true,
	}
}
