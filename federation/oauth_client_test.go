package federation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"orion-auth-backend/model"
)

// mockOIDCServer serves a minimal but valid discovery document so that
// oidc.NewProvider succeeds without contacting the real network.
func mockOIDCServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)

	disco := map[string]any{
		"issuer":                 srv.URL,
		"authorization_endpoint": srv.URL + "/authorize",
		"token_endpoint":         srv.URL + "/token",
		"userinfo_endpoint":      srv.URL + "/userinfo",
		"jwks_uri":               srv.URL + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	}
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(disco)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})
	return srv
}

func TestBuilder_ForProvider_OIDCBuildsConfigFromDiscovery(t *testing.T) {
	srv := mockOIDCServer(t)
	defer srv.Close()

	id, _ := uuid.NewV7()
	iss := srv.URL
	provider := &model.FederationProvider{
		BaseModel: model.BaseModel{ID: id},
		Name:      "mock",
		Type:      ProviderTypeOIDC,
		ClientID:  "client-xyz",
		IssuerURL: &iss,
		Scopes:    []string{"openid", "email"},
	}

	b := NewBuilder()
	oc, err := b.ForProvider(context.Background(), provider, "shh", "https://auth.example.com/cb")
	require.NoError(t, err)

	require.True(t, oc.IsOIDC)
	require.NotNil(t, oc.Verifier)
	assert.Equal(t, srv.URL+"/authorize", oc.Config.Endpoint.AuthURL)
	assert.Equal(t, srv.URL+"/token", oc.Config.Endpoint.TokenURL)
	assert.Equal(t, srv.URL+"/userinfo", oc.UserinfoURL)
	assert.Equal(t, "client-xyz", oc.Config.ClientID)
	assert.Equal(t, "shh", oc.Config.ClientSecret)
	assert.Equal(t, "https://auth.example.com/cb", oc.Config.RedirectURL)
	assert.Equal(t, []string{"openid", "email"}, oc.Config.Scopes)

	// AuthCodeURL must include PKCE + state parameters when callers add them.
	authURL := oc.Config.AuthCodeURL("st4te")
	assert.True(t, strings.HasPrefix(authURL, srv.URL+"/authorize?"))
	assert.Contains(t, authURL, "state=st4te")
	assert.Contains(t, authURL, "client_id=client-xyz")
}

func TestBuilder_CacheReusedUntilProviderUpdated(t *testing.T) {
	srv := mockOIDCServer(t)
	defer srv.Close()

	calls := 0
	original := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			calls++
		}
		original.ServeHTTP(w, r)
	})

	id, _ := uuid.NewV7()
	iss := srv.URL
	provider := &model.FederationProvider{
		BaseModel: model.BaseModel{ID: id},
		Type:      ProviderTypeOIDC,
		ClientID:  "client",
		IssuerURL: &iss,
	}

	b := NewBuilder()
	_, err := b.ForProvider(context.Background(), provider, "s", "https://x/cb")
	require.NoError(t, err)
	_, err = b.ForProvider(context.Background(), provider, "s", "https://x/cb")
	require.NoError(t, err)
	assert.Equal(t, 1, calls, "discovery should be cached across builds")

	b.Invalidate(provider.ID)
	_, err = b.ForProvider(context.Background(), provider, "s", "https://x/cb")
	require.NoError(t, err)
	assert.Equal(t, 2, calls, "discovery should refresh after Invalidate")
}

func TestBuilder_ForProvider_OAuth2BuildsManualEndpoint(t *testing.T) {
	id, _ := uuid.NewV7()
	auth := "https://gh.example.com/login/oauth/authorize"
	token := "https://gh.example.com/login/oauth/access_token"
	userinfo := "https://api.gh.example.com/user"
	provider := &model.FederationProvider{
		BaseModel:        model.BaseModel{ID: id},
		Type:             ProviderTypeOAuth2,
		ClientID:         "gh-app",
		AuthorizationURL: &auth,
		TokenURL:         &token,
		UserinfoURL:      &userinfo,
		Scopes:           []string{"read:user", "user:email"},
	}

	b := NewBuilder()
	oc, err := b.ForProvider(context.Background(), provider, "secret", "https://auth.example.com/cb")
	require.NoError(t, err)
	assert.False(t, oc.IsOIDC)
	assert.Nil(t, oc.Verifier)
	assert.Equal(t, auth, oc.Config.Endpoint.AuthURL)
	assert.Equal(t, token, oc.Config.Endpoint.TokenURL)
	assert.Equal(t, userinfo, oc.UserinfoURL)
}

func TestBuilder_ForProvider_UnsupportedTypeRejected(t *testing.T) {
	id, _ := uuid.NewV7()
	provider := &model.FederationProvider{BaseModel: model.BaseModel{ID: id}, Type: "saml"}
	b := NewBuilder()
	_, err := b.ForProvider(context.Background(), provider, "s", "https://x/cb")
	require.Error(t, err)
}
