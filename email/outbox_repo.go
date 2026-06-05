package email

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"orion-auth-backend/model"
)

// OutboxRepository is the persistence surface for the email outbox.
// The worker's locking semantics (FOR UPDATE SKIP LOCKED) are hidden
// behind ProcessBatch so callers cannot accidentally leak a row out
// of its transaction.
type OutboxRepository interface {
	Enqueue(e *model.OutboundEmail) error

	// ProcessBatch fetches up to `limit` due rows under FOR UPDATE
	// SKIP LOCKED, calls `deliver` for each, and either marks the row
	// sent (deliver returned nil) or bumps attempts/next_retry_at
	// (deliver returned an error). Concurrent workers can call this
	// safely; the SKIP LOCKED clause ensures each row is handled by
	// at most one worker per cycle. Returns the number of rows it
	// touched.
	ProcessBatch(limit int, backoff BackoffFn, deliver func(*model.OutboundEmail) error) (int, error)
}

// BackoffFn computes the delay before the next retry given the current
// attempt count (1-based: the first retry is attempts=1). The worker
// will not call this when attempts >= MaxAttempts (the row is marked
// failed instead).
type BackoffFn func(attempts int) time.Duration

type gormOutboxRepository struct {
	db *gorm.DB
}

// NewOutboxRepository returns the GORM-backed Repository wired in
// main.go. Tests use a fake.
func NewOutboxRepository(db *gorm.DB) OutboxRepository {
	return &gormOutboxRepository{db: db}
}

func (r *gormOutboxRepository) Enqueue(e *model.OutboundEmail) error {
	if e.ID == uuid.Nil {
		id, _ := uuid.NewV7()
		e.ID = id
	}
	if e.MaxAttempts == 0 {
		e.MaxAttempts = 5
	}
	if e.Status == "" {
		e.Status = model.OutboundStatusPending
	}
	return r.db.Create(e).Error
}

func (r *gormOutboxRepository) ProcessBatch(limit int, backoff BackoffFn, deliver func(*model.OutboundEmail) error) (int, error) {
	processed := 0
	err := r.db.Transaction(func(tx *gorm.DB) error {
		var rows []model.OutboundEmail
		err := tx.
			Raw(`SELECT * FROM outbound_emails
			      WHERE status = ? AND next_retry_at <= NOW()
			      ORDER BY next_retry_at
			      LIMIT ?
			      FOR UPDATE SKIP LOCKED`, model.OutboundStatusPending, limit).
			Scan(&rows).Error
		if err != nil {
			return err
		}
		now := tx.NowFunc()
		for i := range rows {
			row := &rows[i]
			deliverErr := deliver(row)
			row.Attempts++
			if deliverErr == nil {
				row.Status = model.OutboundStatusSent
				row.SentAt = &now
				row.LastError = nil
			} else {
				msg := deliverErr.Error()
				row.LastError = &msg
				if row.Attempts >= row.MaxAttempts {
					row.Status = model.OutboundStatusFailed
				} else {
					row.NextRetryAt = now.Add(backoff(row.Attempts))
				}
			}
			if err := tx.Save(row).Error; err != nil {
				return err
			}
			processed++
		}
		return nil
	})
	return processed, err
}

// ExpBackoff is the default BackoffFn: doubles every retry starting
// at 2 minutes, capped at 1 hour. Total retry window with the default
// MaxAttempts=5 is ~30 minutes.
func ExpBackoff(attempts int) time.Duration {
	const base = 2 * time.Minute
	const max = time.Hour
	d := base
	for i := 1; i < attempts; i++ {
		d *= 2
		if d >= max {
			return max
		}
	}
	return d
}
