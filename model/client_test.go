package model

import (
	"testing"

	"github.com/lib/pq"
)

func newTestClient() *OAuthClient {
	return &OAuthClient{
		Scopes:       pq.StringArray{"openid", "profile", "email"},
		RedirectURIs: pq.StringArray{"https://app.example.com/callback", "https://other.example.com/cb"},
		GrantTypes:   pq.StringArray{"authorization_code", "refresh_token"},
	}
}

func TestHasScope(t *testing.T) {
	c := newTestClient()

	if !c.HasScope("openid") {
		t.Error("should have openid scope")
	}
	if c.HasScope("admin") {
		t.Error("should not have admin scope")
	}
}

func TestHasGrantType(t *testing.T) {
	c := newTestClient()

	if !c.HasGrantType("authorization_code") {
		t.Error("should have authorization_code grant type")
	}
	if c.HasGrantType("client_credentials") {
		t.Error("should not have client_credentials grant type")
	}
}

func TestHasRedirectURI(t *testing.T) {
	c := newTestClient()

	if !c.HasRedirectURI("https://app.example.com/callback") {
		t.Error("should have matching redirect URI")
	}
	if c.HasRedirectURI("https://evil.com/callback") {
		t.Error("should not have unregistered redirect URI")
	}
}

func TestValidateScopes(t *testing.T) {
	c := newTestClient()

	// All valid
	valid := c.ValidateScopes([]string{"openid", "profile"})
	if len(valid) != 2 {
		t.Errorf("expected 2 valid scopes, got %d", len(valid))
	}

	// Mixed valid and invalid
	valid = c.ValidateScopes([]string{"openid", "admin", "email"})
	if len(valid) != 2 {
		t.Errorf("expected 2 valid scopes, got %d", len(valid))
	}

	// None valid
	valid = c.ValidateScopes([]string{"admin", "superuser"})
	if len(valid) != 0 {
		t.Errorf("expected 0 valid scopes, got %d", len(valid))
	}

	// Empty request returns all client scopes
	valid = c.ValidateScopes(nil)
	if len(valid) != 3 {
		t.Errorf("expected 3 default scopes, got %d", len(valid))
	}
}
