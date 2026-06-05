package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/gin-gonic/gin"
)

type stubProbe struct{ active bool }

func (s stubProbe) HasActiveKey() bool { return s.active }

func TestReadinessCheck(t *testing.T) {
	gin.SetMode(gin.TestMode)

	pingOK := func() error { return nil }
	pingFail := func() error { return errors.New("connection refused") }

	cases := []struct {
		name       string
		ping       dbPing
		probe      readinessProbe
		wantStatus int
		wantDB     string
		wantJWKS   string
	}{
		{
			name:       "all healthy",
			ping:       pingOK,
			probe:      stubProbe{active: true},
			wantStatus: http.StatusOK,
			wantDB:     "ok",
			wantJWKS:   "ok",
		},
		{
			name:       "db ping fails",
			ping:       pingFail,
			probe:      stubProbe{active: true},
			wantStatus: http.StatusServiceUnavailable,
			wantDB:     "unreachable",
			wantJWKS:   "ok",
		},
		{
			name:       "no active signing key",
			ping:       pingOK,
			probe:      stubProbe{active: false},
			wantStatus: http.StatusServiceUnavailable,
			wantDB:     "ok",
			wantJWKS:   "no active signing key",
		},
		{
			name:       "nil probe = not ready",
			ping:       pingOK,
			probe:      nil,
			wantStatus: http.StatusServiceUnavailable,
			wantDB:     "ok",
			wantJWKS:   "no active signing key",
		},
		{
			name:       "nil ping = db unavailable",
			ping:       nil,
			probe:      stubProbe{active: true},
			wantStatus: http.StatusServiceUnavailable,
			wantDB:     "unavailable",
			wantJWKS:   "ok",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.GET("/ready", readinessCheck(tc.ping, tc.probe))

			w := httptest.NewRecorder()
			req, _ := http.NewRequest(http.MethodGet, "/ready", nil)
			r.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body=%s)", w.Code, tc.wantStatus, w.Body.String())
			}

			var body struct {
				Status string            `json:"status"`
				Checks map[string]string `json:"checks"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body.Checks["database"] != tc.wantDB {
				t.Errorf("checks.database = %q, want %q", body.Checks["database"], tc.wantDB)
			}
			if body.Checks["jwks"] != tc.wantJWKS {
				t.Errorf("checks.jwks = %q, want %q", body.Checks["jwks"], tc.wantJWKS)
			}
		})
	}
}

func TestHealthCheck_AlwaysOK(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/health", healthCheck)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/health", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if matched, _ := regexp.MatchString(`"status":"ok"`, w.Body.String()); !matched {
		t.Errorf("body = %q, want status:ok", w.Body.String())
	}
}
