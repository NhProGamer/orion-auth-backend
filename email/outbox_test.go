package email

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"orion-auth-backend/model"
)

// fakeOutboxRepo simulates the Postgres FOR UPDATE SKIP LOCKED
// semantics in memory: ProcessBatch hands out at most `limit` due
// rows and another concurrent call sees the remaining ones.
type fakeOutboxRepo struct {
	mu     sync.Mutex
	rows   []model.OutboundEmail
	clock  time.Time
	leased map[string]bool // simulates locked rows during ProcessBatch
}

func newFakeOutboxRepo() *fakeOutboxRepo {
	return &fakeOutboxRepo{
		clock:  time.Now(),
		leased: map[string]bool{},
	}
}

func (r *fakeOutboxRepo) now() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.clock
}

func (r *fakeOutboxRepo) advance(d time.Duration) {
	r.mu.Lock()
	r.clock = r.clock.Add(d)
	r.mu.Unlock()
}

func (r *fakeOutboxRepo) Enqueue(e *model.OutboundEmail) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e.Status == "" {
		e.Status = model.OutboundStatusPending
	}
	if e.MaxAttempts == 0 {
		e.MaxAttempts = 5
	}
	if e.NextRetryAt.IsZero() {
		e.NextRetryAt = r.clock
	}
	e.CreatedAt = r.clock
	r.rows = append(r.rows, *e)
	return nil
}

// EnqueueInTx ignores the Tx in tests — the fake has no notion of
// rollback. Tests that need to assert rollback semantics use a
// separate harness that drives the real gorm Tx.
func (r *fakeOutboxRepo) EnqueueInTx(_ *gorm.DB, e *model.OutboundEmail) error {
	return r.Enqueue(e)
}

// PendingCount mirrors the production repository: count rows still in
// the pending status. Used by the worker's metrics tick.
func (r *fakeOutboxRepo) PendingCount() (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for _, row := range r.rows {
		if row.Status == model.OutboundStatusPending {
			n++
		}
	}
	return n, nil
}

func (r *fakeOutboxRepo) ProcessBatch(limit int, backoff BackoffFn, deliver func(*model.OutboundEmail) error) (int, error) {
	r.mu.Lock()
	now := r.clock
	// Lease up to `limit` due, pending, unlocked rows.
	var leased []int
	for i := range r.rows {
		if len(leased) == limit {
			break
		}
		row := &r.rows[i]
		if row.Status != model.OutboundStatusPending {
			continue
		}
		if row.NextRetryAt.After(now) {
			continue
		}
		if r.leased[row.ID.String()] {
			continue
		}
		r.leased[row.ID.String()] = true
		leased = append(leased, i)
	}
	r.mu.Unlock()

	for _, idx := range leased {
		row := &r.rows[idx]
		deliverErr := deliver(row)
		r.mu.Lock()
		row.Attempts++
		if deliverErr == nil {
			row.Status = model.OutboundStatusSent
			sentAt := r.clock
			row.SentAt = &sentAt
			row.LastError = nil
		} else {
			msg := deliverErr.Error()
			row.LastError = &msg
			if row.Attempts >= row.MaxAttempts {
				row.Status = model.OutboundStatusFailed
			} else {
				row.NextRetryAt = r.clock.Add(backoff(row.Attempts))
			}
		}
		delete(r.leased, row.ID.String())
		r.mu.Unlock()
	}
	return len(leased), nil
}

func TestOutboxSender_EnqueuesRenderedRow(t *testing.T) {
	repo := newFakeOutboxRepo()
	s := NewOutboxSender(repo, "https://auth.example.test", NewResolver(nil))

	if err := s.SendVerificationEmail("alice@example.test", "vtok"); err != nil {
		t.Fatalf("SendVerificationEmail: %v", err)
	}

	if len(repo.rows) != 1 {
		t.Fatalf("rows enqueued: %d, want 1", len(repo.rows))
	}
	row := repo.rows[0]
	if row.Recipient != "alice@example.test" {
		t.Errorf("recipient = %q", row.Recipient)
	}
	if row.Subject != "Verify your email address" {
		t.Errorf("subject = %q", row.Subject)
	}
	if row.Status != model.OutboundStatusPending {
		t.Errorf("status = %q, want pending", row.Status)
	}
	if !strings.Contains(row.BodyHTML, "vtok") {
		t.Errorf("body does not contain token; body=%s", row.BodyHTML)
	}
	if !strings.Contains(row.BodyHTML, "https://auth.example.test") {
		t.Errorf("body does not contain issuer; body=%s", row.BodyHTML)
	}
}

func TestOutboxSender_AllMethodsEnqueue(t *testing.T) {
	// Smoke test: every Send* method must succeed against the in-mem
	// repo and produce a row. Catches a future template name typo or
	// missing template at compile-time-ish.
	repo := newFakeOutboxRepo()
	s := NewOutboxSender(repo, "https://auth.example.test", NewResolver(nil))

	check := func(label string, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("%s: %v", label, err)
		}
	}
	check("verify", s.SendVerificationEmail("a@test", "t"))
	check("reset", s.SendPasswordResetEmail("a@test", "t"))
	check("invite", s.SendInvitationEmail("a@test", "t"))
	check("email-change-conf", s.SendEmailChangeConfirmation("a@test", "t"))
	check("email-changed-notice", s.SendEmailChangedNotice("old@test", "new@test"))
	check("pwd-changed-notice", s.SendPasswordChangedNotice("a@test"))
	check("account-deletion", s.SendAccountDeletionEmail("a@test", "t"))

	if len(repo.rows) != 7 {
		t.Errorf("enqueued %d rows, want 7", len(repo.rows))
	}
}

type stubDeliverer struct {
	calls   int
	failFor int // first N calls return err
	lastErr error
}

func (d *stubDeliverer) Deliver(to, subject, body string) error {
	d.calls++
	if d.calls <= d.failFor {
		d.lastErr = errors.New("smtp 421 try again")
		return d.lastErr
	}
	return nil
}

func TestWorker_MarksSentOnSuccess(t *testing.T) {
	repo := newFakeOutboxRepo()
	_ = NewOutboxSender(repo, "x", NewResolver(nil)).SendVerificationEmail("a@test", "t")

	w := NewOutboxWorker(repo, &stubDeliverer{})
	w.tick(testCtx())

	if repo.rows[0].Status != model.OutboundStatusSent {
		t.Errorf("status = %q, want sent", repo.rows[0].Status)
	}
	if repo.rows[0].SentAt == nil {
		t.Error("SentAt should be set")
	}
	if repo.rows[0].Attempts != 1 {
		t.Errorf("attempts = %d, want 1", repo.rows[0].Attempts)
	}
}

func TestWorker_BackoffOnTransientFailure(t *testing.T) {
	repo := newFakeOutboxRepo()
	_ = NewOutboxSender(repo, "x", NewResolver(nil)).SendPasswordResetEmail("a@test", "t")

	w := NewOutboxWorker(repo, &stubDeliverer{failFor: 100})
	w.tick(testCtx())

	row := repo.rows[0]
	if row.Status != model.OutboundStatusPending {
		t.Errorf("status = %q, want pending (will retry)", row.Status)
	}
	if row.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", row.Attempts)
	}
	if row.LastError == nil || !strings.Contains(*row.LastError, "smtp 421") {
		t.Errorf("LastError not recorded: %v", row.LastError)
	}
	// next_retry must be in the future (>= 2 minutes per ExpBackoff(1)).
	if !row.NextRetryAt.After(repo.now()) {
		t.Errorf("next_retry_at = %v, want > now (%v)", row.NextRetryAt, repo.now())
	}
}

func TestWorker_MarksFailedAtMaxAttempts(t *testing.T) {
	repo := newFakeOutboxRepo()
	repo.rows = append(repo.rows, model.OutboundEmail{
		ID:          uuidNew(t),
		Recipient:   "a@test",
		Subject:     "x",
		BodyHTML:    "body",
		Status:      model.OutboundStatusPending,
		Attempts:    4, // about to become 5 = max
		MaxAttempts: 5,
		NextRetryAt: repo.now(),
	})
	w := NewOutboxWorker(repo, &stubDeliverer{failFor: 100})
	w.tick(testCtx())

	if repo.rows[0].Status != model.OutboundStatusFailed {
		t.Errorf("status = %q, want failed", repo.rows[0].Status)
	}
}

func TestWorker_SkipsNotYetDueRows(t *testing.T) {
	repo := newFakeOutboxRepo()
	_ = NewOutboxSender(repo, "x", NewResolver(nil)).SendVerificationEmail("a@test", "t")
	// Push the row 5 minutes into the future.
	repo.rows[0].NextRetryAt = repo.now().Add(5 * time.Minute)

	d := &stubDeliverer{}
	w := NewOutboxWorker(repo, d)
	w.tick(testCtx())

	if d.calls != 0 {
		t.Errorf("Deliver called %d times, want 0 (row not yet due)", d.calls)
	}
	if repo.rows[0].Status != model.OutboundStatusPending {
		t.Errorf("status = %q, want pending", repo.rows[0].Status)
	}
}

func TestExpBackoffMonotonicAndCapped(t *testing.T) {
	prev := time.Duration(0)
	for i := 1; i <= 8; i++ {
		d := ExpBackoff(i)
		if d < prev {
			t.Errorf("ExpBackoff(%d) = %v < prev %v (non-monotonic)", i, d, prev)
		}
		if d > time.Hour {
			t.Errorf("ExpBackoff(%d) = %v > cap 1h", i, d)
		}
		prev = d
	}
	if ExpBackoff(8) != time.Hour {
		t.Errorf("ExpBackoff(8) = %v, want 1h cap reached", ExpBackoff(8))
	}
}
