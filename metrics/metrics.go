// Package metrics exposes Prometheus instrumentation for the auth server.
//
// All metrics live on the default Prometheus registry so the standard
// process_* and go_* collectors are scraped for free. Call the
// Record* helpers from handler code to advance counters; the Gin
// middleware emits the request-duration histogram automatically.
package metrics

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"net/http"
)

var (
	loginsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "orionauth_login_total",
			Help: "User login attempts by terminal outcome.",
		},
		[]string{"result"}, // success | fail | locked | mfa_required | email_not_verified
	)

	tokensIssued = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "orionauth_oauth_token_issued_total",
			Help: "Access tokens issued at the token endpoint by grant type. Failures are observable via orionauth_http_request_duration_seconds{route=\"/token\",status!~\"2..\"}.",
		},
		[]string{"grant_type"},
	)

	requestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "orionauth_http_request_duration_seconds",
			Help:    "HTTP request latency in seconds, observed at the Gin handler boundary.",
			Buckets: prometheus.DefBuckets, // 0.005..10s, sufficient for an auth API
		},
		[]string{"method", "route", "status"},
	)
)

// Handler returns the Prometheus exposition endpoint. Mount it at
// /metrics on the gin engine.
func Handler() http.Handler {
	return promhttp.Handler()
}

// HTTPDuration is a Gin middleware that observes per-request latency
// in the request_duration histogram, labelled by method, matched
// route, and status code. We use the *route template* (e.g.
// "/api/v1/users/:id") rather than the raw path so high-cardinality
// IDs don't blow up the metric series count.
func HTTPDuration() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		requestDuration.
			WithLabelValues(c.Request.Method, route, strconv.Itoa(c.Writer.Status())).
			Observe(time.Since(start).Seconds())
	}
}

// RecordLogin advances orionauth_login_total{result}. Result values
// are constrained to the documented set in the metric Help; callers
// should use the constants below.
func RecordLogin(result string) {
	loginsTotal.WithLabelValues(result).Inc()
}

const (
	LoginSuccess          = "success"
	LoginFail             = "fail"
	LoginLocked           = "locked"
	LoginMFARequired      = "mfa_required"
	LoginEmailNotVerified = "email_not_verified"
)

// LoginOutcomeFromError maps an AppError code (account_locked,
// email_not_verified) to the corresponding metrics label, defaulting
// to LoginFail for the generic invalid-credentials case. Centralised
// so both /api/v1/auth/login and /authorize/login feed the same
// bucket vocabulary.
func LoginOutcomeFromError(code string) string {
	switch code {
	case "account_locked":
		return LoginLocked
	case "email_not_verified":
		return LoginEmailNotVerified
	default:
		return LoginFail
	}
}

// RecordTokenIssued advances orionauth_oauth_token_issued_total{grant_type}.
func RecordTokenIssued(grantType string) {
	tokensIssued.WithLabelValues(grantType).Inc()
}
