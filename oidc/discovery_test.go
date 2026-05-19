package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func newDiscoveryRouter(issuer string) (*gin.Engine, *Service) {
	gin.SetMode(gin.TestMode)
	svc := &Service{issuer: issuer}
	h := NewHandler(svc)
	r := gin.New()
	r.GET("/.well-known/openid-configuration", h.Discovery)
	r.GET("/.well-known/oauth-authorization-server", h.OAuthDiscovery)
	return r, svc
}

func getDiscoveryJSON(t *testing.T, r *gin.Engine, path string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", path, w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return body
}

func TestDiscovery_OIDCRequiredFields(t *testing.T) {
	r, _ := newDiscoveryRouter("https://auth.example.com")
	body := getDiscoveryJSON(t, r, "/.well-known/openid-configuration")

	required := []string{
		"issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint",
		"jwks_uri", "subject_types_supported", "id_token_signing_alg_values_supported",
		"response_types_supported", "claims_supported", "scopes_supported",
	}
	for _, k := range required {
		if _, ok := body[k]; !ok {
			t.Errorf("missing required OIDC field %q", k)
		}
	}
	if iss, _ := body["issuer"].(string); iss != "https://auth.example.com" {
		t.Errorf("issuer = %q", iss)
	}
}

func TestOAuthDiscovery_RFC8414RequiredFields(t *testing.T) {
	r, _ := newDiscoveryRouter("https://auth.example.com")
	body := getDiscoveryJSON(t, r, "/.well-known/oauth-authorization-server")

	required := []string{
		"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
		"response_types_supported", "grant_types_supported",
		"token_endpoint_auth_methods_supported",
	}
	for _, k := range required {
		if _, ok := body[k]; !ok {
			t.Errorf("missing required RFC 8414 field %q", k)
		}
	}
}

func TestOAuthDiscovery_OmitsOIDCOnlyFields(t *testing.T) {
	r, _ := newDiscoveryRouter("https://auth.example.com")
	body := getDiscoveryJSON(t, r, "/.well-known/oauth-authorization-server")

	mustOmit := []string{
		"userinfo_endpoint",
		"subject_types_supported",
		"id_token_signing_alg_values_supported",
		"claims_supported",
		"end_session_endpoint",
		"check_session_iframe",
		"backchannel_logout_supported",
		"backchannel_logout_session_supported",
		"frontchannel_logout_supported",
		"frontchannel_logout_session_supported",
		"userinfo_signing_alg_values_supported",
		"claims_parameter_supported",
	}
	for _, k := range mustOmit {
		if _, present := body[k]; present {
			t.Errorf("OAuth metadata should not advertise OIDC-only field %q", k)
		}
	}
}

func TestBothDiscoveries_AdvertiseClientSecretJWT(t *testing.T) {
	r, _ := newDiscoveryRouter("https://auth.example.com")
	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		body := getDiscoveryJSON(t, r, path)
		methods, ok := body["token_endpoint_auth_methods_supported"].([]any)
		if !ok {
			t.Fatalf("%s: missing or invalid token_endpoint_auth_methods_supported", path)
		}
		found := false
		for _, m := range methods {
			if s, _ := m.(string); s == "client_secret_jwt" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: client_secret_jwt not advertised in %v", path, methods)
		}
	}
}

func TestBothDiscoveries_AdvertiseRequestURIParameter(t *testing.T) {
	r, _ := newDiscoveryRouter("https://auth.example.com")
	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		body := getDiscoveryJSON(t, r, path)
		if v, _ := body["request_uri_parameter_supported"].(bool); !v {
			t.Errorf("%s: request_uri_parameter_supported should be true", path)
		}
		algs, ok := body["request_object_signing_alg_values_supported"].([]any)
		if !ok || len(algs) == 0 {
			t.Errorf("%s: missing request_object_signing_alg_values_supported", path)
		}
	}
}

func TestOIDCDiscovery_AdvertisesJWEEncryption(t *testing.T) {
	r, _ := newDiscoveryRouter("https://auth.example.com")
	body := getDiscoveryJSON(t, r, "/.well-known/openid-configuration")

	for _, k := range []string{
		"id_token_encryption_alg_values_supported",
		"id_token_encryption_enc_values_supported",
		"userinfo_encryption_alg_values_supported",
		"userinfo_encryption_enc_values_supported",
	} {
		v, ok := body[k].([]any)
		if !ok || len(v) == 0 {
			t.Errorf("%s should be a non-empty array, got %v", k, body[k])
		}
	}
}

func TestOAuthDiscovery_EndpointsMatchOIDCDiscovery(t *testing.T) {
	r, _ := newDiscoveryRouter("https://auth.example.com")
	oidc := getDiscoveryJSON(t, r, "/.well-known/openid-configuration")
	oauth := getDiscoveryJSON(t, r, "/.well-known/oauth-authorization-server")

	for _, k := range []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "introspection_endpoint", "revocation_endpoint", "device_authorization_endpoint"} {
		if oidc[k] != oauth[k] {
			t.Errorf("%s mismatch: oidc=%v oauth=%v", k, oidc[k], oauth[k])
		}
	}
}
