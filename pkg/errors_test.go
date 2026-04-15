package pkg

import (
	"net/http"
	"testing"
)

func TestOAuthErrorCodes(t *testing.T) {
	tests := []struct {
		name       string
		err        *OAuthError
		wantCode   string
		wantStatus int
	}{
		{"invalid_request", ErrInvalidRequest("bad"), "invalid_request", http.StatusBadRequest},
		{"invalid_client", ErrInvalidClient("bad"), "invalid_client", http.StatusUnauthorized},
		{"invalid_grant", ErrInvalidGrant("bad"), "invalid_grant", http.StatusBadRequest},
		{"invalid_scope", ErrInvalidScope("bad"), "invalid_scope", http.StatusBadRequest},
		{"unsupported_grant_type", ErrUnsupportedGrantType("bad"), "unsupported_grant_type", http.StatusBadRequest},
		{"server_error", ErrServerError("bad"), "server_error", http.StatusInternalServerError},
		{"access_denied", ErrAccessDenied("bad"), "access_denied", http.StatusForbidden},
		{"authorization_pending", ErrAuthorizationPending(), "authorization_pending", http.StatusBadRequest},
		{"slow_down", ErrSlowDown(), "slow_down", http.StatusBadRequest},
		{"expired_token", ErrExpiredToken("bad"), "expired_token", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Code != tt.wantCode {
				t.Errorf("Code = %q, want %q", tt.err.Code, tt.wantCode)
			}
			if tt.err.StatusCode != tt.wantStatus {
				t.Errorf("StatusCode = %d, want %d", tt.err.StatusCode, tt.wantStatus)
			}
		})
	}
}

func TestAppErrorCodes(t *testing.T) {
	tests := []struct {
		name       string
		err        *AppError
		wantCode   string
		wantStatus int
	}{
		{"bad_request", ErrBadRequest("msg"), "bad_request", http.StatusBadRequest},
		{"not_found", ErrNotFound("msg"), "not_found", http.StatusNotFound},
		{"unauthorized", ErrUnauthorized("msg"), "unauthorized", http.StatusUnauthorized},
		{"forbidden", ErrForbidden("msg"), "forbidden", http.StatusForbidden},
		{"conflict", ErrConflict("msg"), "conflict", http.StatusConflict},
		{"internal_error", ErrInternal("msg"), "internal_error", http.StatusInternalServerError},
		{"too_many_requests", ErrTooManyRequests("msg"), "too_many_requests", http.StatusTooManyRequests},
		{"account_locked", ErrAccountLocked("msg"), "account_locked", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Code != tt.wantCode {
				t.Errorf("Code = %q, want %q", tt.err.Code, tt.wantCode)
			}
			if tt.err.StatusCode != tt.wantStatus {
				t.Errorf("StatusCode = %d, want %d", tt.err.StatusCode, tt.wantStatus)
			}
		})
	}
}

func TestOAuthErrorString(t *testing.T) {
	e := ErrInvalidRequest("missing param")
	if e.Error() != "invalid_request: missing param" {
		t.Errorf("Error() = %q", e.Error())
	}

	e2 := &OAuthError{Code: "test"}
	if e2.Error() != "test" {
		t.Errorf("Error() without description = %q", e2.Error())
	}
}
