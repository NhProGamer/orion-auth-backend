package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestHTTPDurationLabelsRouteTemplate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(HTTPDuration())
	r.GET("/users/:id", func(c *gin.Context) { c.Status(http.StatusOK) })

	for _, path := range []string{"/users/alice", "/users/bob", "/users/charlie"} {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, path, nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d for %s", w.Code, path)
		}
	}

	// Scrape /metrics and assert only ONE series exists for the templated
	// route: high-cardinality IDs (alice/bob/charlie) must not leak into
	// labels.
	body := scrapeMetrics(t)
	count := strings.Count(body, `orionauth_http_request_duration_seconds_count{method="GET",route="/users/:id",status="200"}`)
	if count != 1 {
		t.Errorf("expected exactly 1 series for /users/:id, got %d. body:\n%s", count, body)
	}
	if strings.Contains(body, `route="/users/alice"`) {
		t.Errorf("metric leaked raw user id in label; got body:\n%s", body)
	}
}

func TestRecordLoginAndTokenIssued(t *testing.T) {
	// Each Record* call should increment exactly one labelled series.
	RecordLogin(LoginSuccess)
	RecordLogin(LoginFail)
	RecordLogin(LoginLocked)
	RecordTokenIssued("authorization_code")
	RecordTokenIssued("refresh_token")

	body := scrapeMetrics(t)
	wantContains := []string{
		`orionauth_login_total{result="success"}`,
		`orionauth_login_total{result="fail"}`,
		`orionauth_login_total{result="locked"}`,
		`orionauth_oauth_token_issued_total{grant_type="authorization_code"}`,
		`orionauth_oauth_token_issued_total{grant_type="refresh_token"}`,
	}
	for _, w := range wantContains {
		if !strings.Contains(body, w) {
			t.Errorf("scraped body missing %q", w)
		}
	}
}

func TestLoginOutcomeFromError(t *testing.T) {
	cases := []struct {
		code string
		want string
	}{
		{"account_locked", LoginLocked},
		{"email_not_verified", LoginEmailNotVerified},
		{"unauthorized", LoginFail},
		{"", LoginFail},
	}
	for _, tc := range cases {
		if got := LoginOutcomeFromError(tc.code); got != tc.want {
			t.Errorf("LoginOutcomeFromError(%q) = %q, want %q", tc.code, got, tc.want)
		}
	}
}

func scrapeMetrics(t *testing.T) string {
	t.Helper()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/metrics", nil)
	Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d", w.Code)
	}
	return w.Body.String()
}
