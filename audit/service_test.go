package audit

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"orion-auth-backend/model"
)

type fakeRepo struct {
	created    []model.AuditLog
	createErr  error
	queryLogs  []model.AuditLog
	queryTotal int64
	queryErr   error
	gotInput   QueryInput
}

func (r *fakeRepo) Create(log *model.AuditLog) error {
	if r.createErr != nil {
		return r.createErr
	}
	r.created = append(r.created, *log)
	return nil
}

func (r *fakeRepo) Query(input QueryInput) ([]model.AuditLog, int64, error) {
	r.gotInput = input
	return r.queryLogs, r.queryTotal, r.queryErr
}

func TestLog_HappyPath(t *testing.T) {
	repo := &fakeRepo{}
	svc := NewServiceWithRepository(repo)

	userID := uuid.New()
	clientID := uuid.New()
	svc.Log(LogEntry{
		UserID:    &userID,
		ClientID:  &clientID,
		Action:    "user.login",
		IPAddress: "192.0.2.1",
		UserAgent: "TestAgent/1.0",
		Metadata:  map[string]any{"flow": "oauth", "scope": "openid"},
	})

	if len(repo.created) != 1 {
		t.Fatalf("Create called %d times, want 1", len(repo.created))
	}
	got := repo.created[0]

	if got.ID == uuid.Nil {
		t.Error("ID should be assigned via uuid v7")
	}
	if got.UserID == nil || *got.UserID != userID {
		t.Errorf("UserID = %v, want %v", got.UserID, userID)
	}
	if got.ClientID == nil || *got.ClientID != clientID {
		t.Errorf("ClientID = %v, want %v", got.ClientID, clientID)
	}
	if got.Action != "user.login" {
		t.Errorf("Action = %q, want user.login", got.Action)
	}
	if got.IPAddress == nil || *got.IPAddress != "192.0.2.1" {
		t.Errorf("IPAddress = %v, want 192.0.2.1", got.IPAddress)
	}
	if got.UserAgent == nil || *got.UserAgent != "TestAgent/1.0" {
		t.Errorf("UserAgent = %v, want TestAgent/1.0", got.UserAgent)
	}

	var meta map[string]any
	if err := json.Unmarshal(got.Metadata, &meta); err != nil {
		t.Fatalf("metadata is not valid JSON: %v (raw=%s)", err, string(got.Metadata))
	}
	if meta["flow"] != "oauth" || meta["scope"] != "openid" {
		t.Errorf("metadata round-trip lost values: %v", meta)
	}
}

func TestLog_EmptyOptionalFields(t *testing.T) {
	repo := &fakeRepo{}
	svc := NewServiceWithRepository(repo)

	// IPAddress and UserAgent default to "" — repo must see nil pointers,
	// not empty-string pointers (Postgres inet rejects "").
	svc.Log(LogEntry{Action: "system.boot"})

	got := repo.created[0]
	if got.IPAddress != nil {
		t.Errorf("IPAddress should be nil when empty, got %v", *got.IPAddress)
	}
	if got.UserAgent != nil {
		t.Errorf("UserAgent should be nil when empty, got %v", *got.UserAgent)
	}
	// Nil metadata is normalized to empty JSON object so the jsonb
	// column never carries SQL NULL.
	if string(got.Metadata) != "{}" {
		t.Errorf("Metadata = %s, want {}", string(got.Metadata))
	}
}

func TestLog_RepoFailureIsSwallowed(t *testing.T) {
	// An audit-write outage must not propagate. The caller is typically
	// a hot path (login, token issuance) and we'd rather lose a log
	// line than fail the user request.
	repo := &fakeRepo{createErr: errors.New("db connection refused")}
	svc := NewServiceWithRepository(repo)

	// Must not panic, must not return.
	svc.Log(LogEntry{Action: "user.login"})
}

func TestQuery_PassesInputThrough(t *testing.T) {
	uid := uuid.New()
	from := time.Now().Add(-24 * time.Hour)
	to := time.Now()

	want := QueryInput{
		UserID:       &uid,
		Action:       "user.login",
		ActionPrefix: "user.",
		From:         &from,
		To:           &to,
		Page:         2,
		PerPage:      50,
	}
	repo := &fakeRepo{
		queryLogs:  []model.AuditLog{{ID: uuid.New(), Action: "user.login"}},
		queryTotal: 1,
	}
	svc := NewServiceWithRepository(repo)

	logs, total, err := svc.Query(want)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if total != 1 || len(logs) != 1 {
		t.Fatalf("logs/total mismatch: %d / %d", len(logs), total)
	}
	if repo.gotInput.UserID == nil || *repo.gotInput.UserID != uid {
		t.Errorf("UserID not forwarded: %v", repo.gotInput.UserID)
	}
	if repo.gotInput.Action != "user.login" || repo.gotInput.ActionPrefix != "user." {
		t.Errorf("Action filters dropped: %+v", repo.gotInput)
	}
	if repo.gotInput.Page != 2 || repo.gotInput.PerPage != 50 {
		t.Errorf("pagination dropped: %d/%d", repo.gotInput.Page, repo.gotInput.PerPage)
	}
}

func TestQuery_PropagatesError(t *testing.T) {
	want := errors.New("db gone")
	repo := &fakeRepo{queryErr: want}
	svc := NewServiceWithRepository(repo)

	_, _, err := svc.Query(QueryInput{Page: 1, PerPage: 10})
	if !errors.Is(err, want) {
		t.Errorf("err = %v, want %v", err, want)
	}
}
