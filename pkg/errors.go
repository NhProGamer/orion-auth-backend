package pkg

import "net/http"

// OAuthError represents an error as defined by RFC 6749 Section 5.2.
type OAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
	StatusCode  int    `json:"-"`
}

func (e *OAuthError) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

// Standard OAuth2 error constructors (RFC 6749 Section 5.2).

func ErrInvalidRequest(desc string) *OAuthError {
	return &OAuthError{Code: "invalid_request", Description: desc, StatusCode: http.StatusBadRequest}
}

func ErrUnauthorizedClient(desc string) *OAuthError {
	return &OAuthError{Code: "unauthorized_client", Description: desc, StatusCode: http.StatusForbidden}
}

func ErrAccessDenied(desc string) *OAuthError {
	return &OAuthError{Code: "access_denied", Description: desc, StatusCode: http.StatusForbidden}
}

func ErrUnsupportedResponseType(desc string) *OAuthError {
	return &OAuthError{Code: "unsupported_response_type", Description: desc, StatusCode: http.StatusBadRequest}
}

func ErrInvalidScope(desc string) *OAuthError {
	return &OAuthError{Code: "invalid_scope", Description: desc, StatusCode: http.StatusBadRequest}
}

func ErrServerError(desc string) *OAuthError {
	return &OAuthError{Code: "server_error", Description: desc, StatusCode: http.StatusInternalServerError}
}

func ErrUnsupportedGrantType(desc string) *OAuthError {
	return &OAuthError{Code: "unsupported_grant_type", Description: desc, StatusCode: http.StatusBadRequest}
}

func ErrInvalidGrant(desc string) *OAuthError {
	return &OAuthError{Code: "invalid_grant", Description: desc, StatusCode: http.StatusBadRequest}
}

func ErrInvalidClient(desc string) *OAuthError {
	return &OAuthError{Code: "invalid_client", Description: desc, StatusCode: http.StatusUnauthorized}
}

// RFC 8628 Device Flow errors.

func ErrAuthorizationPending() *OAuthError {
	return &OAuthError{Code: "authorization_pending", Description: "authorization request is still pending", StatusCode: http.StatusBadRequest}
}

func ErrSlowDown() *OAuthError {
	return &OAuthError{Code: "slow_down", Description: "polling too frequently", StatusCode: http.StatusBadRequest}
}

func ErrExpiredToken(desc string) *OAuthError {
	return &OAuthError{Code: "expired_token", Description: desc, StatusCode: http.StatusBadRequest}
}

// OIDC Core errors (OpenID Connect Core 1.0 Section 3.1.2.6).

func ErrLoginRequired(desc string) *OAuthError {
	return &OAuthError{Code: "login_required", Description: desc, StatusCode: http.StatusBadRequest}
}

func ErrConsentRequired(desc string) *OAuthError {
	return &OAuthError{Code: "consent_required", Description: desc, StatusCode: http.StatusBadRequest}
}

func ErrInteractionRequired(desc string) *OAuthError {
	return &OAuthError{Code: "interaction_required", Description: desc, StatusCode: http.StatusBadRequest}
}

func ErrAccountSelectionRequired(desc string) *OAuthError {
	return &OAuthError{Code: "account_selection_required", Description: desc, StatusCode: http.StatusBadRequest}
}

// Application-level errors (not OAuth2 spec, but used for API responses).

type AppError struct {
	Message    string `json:"message"`
	Code       string `json:"code,omitempty"`
	StatusCode int    `json:"-"`
}

func (e *AppError) Error() string {
	return e.Message
}

func ErrBadRequest(msg string) *AppError {
	return &AppError{Message: msg, Code: "bad_request", StatusCode: http.StatusBadRequest}
}

func ErrNotFound(msg string) *AppError {
	return &AppError{Message: msg, Code: "not_found", StatusCode: http.StatusNotFound}
}

func ErrUnauthorized(msg string) *AppError {
	return &AppError{Message: msg, Code: "unauthorized", StatusCode: http.StatusUnauthorized}
}

func ErrForbidden(msg string) *AppError {
	return &AppError{Message: msg, Code: "forbidden", StatusCode: http.StatusForbidden}
}

func ErrConflict(msg string) *AppError {
	return &AppError{Message: msg, Code: "conflict", StatusCode: http.StatusConflict}
}

func ErrInternal(msg string) *AppError {
	return &AppError{Message: msg, Code: "internal_error", StatusCode: http.StatusInternalServerError}
}

func ErrTooManyRequests(msg string) *AppError {
	return &AppError{Message: msg, Code: "too_many_requests", StatusCode: http.StatusTooManyRequests}
}

func ErrAccountLocked(msg string) *AppError {
	return &AppError{Message: msg, Code: "account_locked", StatusCode: http.StatusForbidden}
}
