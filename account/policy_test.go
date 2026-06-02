package account

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/middleware"
	"orion-auth-backend/model"
	"orion-auth-backend/user"
)

// --- Stubs --------------------------------------------------------------

type stubUserStore struct {
	users map[uuid.UUID]*model.User
}

func (s *stubUserStore) GetByID(id uuid.UUID) (*model.User, error) {
	if u, ok := s.users[id]; ok {
		return u, nil
	}
	return nil, nil
}
func (s *stubUserStore) FindByEmail(string) (*model.User, error)            { return nil, nil }
func (s *stubUserStore) FindByEmailChangeToken(string) (*model.User, error) { return nil, nil }
func (s *stubUserStore) FindByDeletionToken(string) (*model.User, error)    { return nil, nil }
func (s *stubUserStore) UpdateFields(uuid.UUID, map[string]any) error       { return nil }
func (s *stubUserStore) ChangePassword(uuid.UUID, user.ChangePasswordInput) error {
	return nil
}
func (s *stubUserStore) SetInitialPassword(uuid.UUID, string) error { return nil }

type stubRoleProvider struct{}

func (stubRoleProvider) GetUserRoleNames(uuid.UUID) ([]string, error)   { return nil, nil }
func (stubRoleProvider) GetUserPermissions(uuid.UUID) ([]string, error) { return nil, nil }

type stubMFA struct{}

func (stubMFA) HasMFA(uuid.UUID) (bool, error) { return false, nil }

type stubPasskey struct{}

func (stubPasskey) HasUserVerifiedPasskey(uuid.UUID) (bool, error) { return false, nil }

type erroringEvaluator struct{}

func (erroringEvaluator) Evaluate(context.Context, string, map[string]any) (*PolicyResult, error) {
	return nil, errors.New("opa unreachable")
}

// --- Tests --------------------------------------------------------------

// TestPolicyGate_FailsOpenOnEvalErrorButWarns verifies the design contract:
// account_action policies must NOT lock a user out of their own account
// when the evaluator dies, but every fail-open path must emit a WARN log
// so operators can spot a misbehaving policy without digging through
// request traces.
func TestPolicyGate_FailsOpenOnEvalErrorButWarns(t *testing.T) {
	gin.SetMode(gin.TestMode)

	uid, _ := uuid.NewV7()
	users := &stubUserStore{users: map[uuid.UUID]*model.User{
		uid: {BaseModel: model.BaseModel{ID: uid, CreatedAt: time.Now().Add(-30 * 24 * time.Hour)}, Email: "x@example.com"},
	}}
	gate := NewPolicyGate(users, stubRoleProvider{}, stubMFA{}, stubPasskey{}, erroringEvaluator{})

	// Capture slog output.
	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(middleware.ContextUserID, uid)
		c.Next()
	})
	r.Use(gate.Middleware("change_email"))
	called := false
	r.GET("/me/email", func(c *gin.Context) {
		called = true
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/me/email", nil)
	r.ServeHTTP(w, req)

	if !called {
		t.Fatal("PolicyGate must fail-open on account_action when evaluator errors")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (fail-open), got %d", w.Code)
	}
	logs := buf.String()
	if !strings.Contains(logs, "account_action policy evaluation failed") {
		t.Errorf("expected a WARN log naming the failure, got: %s", logs)
	}
	if !strings.Contains(logs, "change_email") {
		t.Errorf("expected the failed action name in the log, got: %s", logs)
	}
}
