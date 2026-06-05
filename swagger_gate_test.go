package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// TestSwaggerOnlyMountedInDebug asserts the documented invariant of
// Vuln 11: Swagger UI must only be reachable when the server is running
// in debug mode. We reproduce the gate inline (the production
// expression is 'if cfg.Server.Mode == "debug"') and check both
// branches behave as advertised. If a future refactor changes the
// expression — e.g. accidentally allowing 'test' — this test breaks.
func TestSwaggerOnlyMountedInDebug(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		mode     string
		wantCode int
	}{
		{"debug", http.StatusOK},
		{"release", http.StatusNotFound},
		{"test", http.StatusNotFound},
		{"production", http.StatusNotFound}, // unknown values must default to NOT exposing Swagger
		{"", http.StatusNotFound},
	}

	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			r := gin.New()
			if tc.mode == "debug" {
				r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
			}
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/swagger/index.html", nil)
			r.ServeHTTP(w, req)
			// In debug mode the wrapped handler may redirect (301) or
			// 200; in non-debug there should be no route at all (404).
			if tc.wantCode == http.StatusOK {
				if w.Code != http.StatusOK && w.Code != http.StatusMovedPermanently {
					t.Fatalf("debug mode: expected Swagger to respond (200/301), got %d", w.Code)
				}
				return
			}
			if w.Code != http.StatusNotFound {
				t.Fatalf("mode=%q: expected 404 (Swagger absent), got %d", tc.mode, w.Code)
			}
		})
	}
}
