package email

import (
	"context"
	"log/slog"
	"time"

	"orion-auth-backend/model"
)

// Deliverer is the side of the worker that actually puts the bytes
// on the wire. Production wires it to SMTPSender.Deliver; tests can
// stub it to simulate transient failures.
type Deliverer interface {
	Deliver(to, subject, htmlBody string) error
}

// OutboxWorker polls the outbox table on a fixed interval, leases
// due rows under FOR UPDATE SKIP LOCKED, and hands each one to the
// Deliverer. Successful deliveries mark the row sent; failures bump
// attempts and reschedule via the BackoffFn. Safe to run with
// multiple instances — the SKIP LOCKED semantics partition rows.
type OutboxWorker struct {
	repo      OutboxRepository
	deliver   Deliverer
	backoff   BackoffFn
	batchSize int
	interval  time.Duration
}

// NewOutboxWorker uses sensible defaults: batch=10, interval=15s,
// backoff=ExpBackoff. Callers tweak via the setters if needed.
func NewOutboxWorker(repo OutboxRepository, deliver Deliverer) *OutboxWorker {
	return &OutboxWorker{
		repo:      repo,
		deliver:   deliver,
		backoff:   ExpBackoff,
		batchSize: 10,
		interval:  15 * time.Second,
	}
}

func (w *OutboxWorker) SetInterval(d time.Duration) { w.interval = d }
func (w *OutboxWorker) SetBatchSize(n int)          { w.batchSize = n }
func (w *OutboxWorker) SetBackoff(b BackoffFn)      { w.backoff = b }

// Start blocks until ctx is cancelled, polling at the configured
// interval. Call as a goroutine from main; the polite shutdown is
// done by cancelling the context.
func (w *OutboxWorker) Start(ctx context.Context) {
	slog.Info("email outbox worker started",
		"interval", w.interval, "batch_size", w.batchSize)
	// Run one tick immediately on startup so a backlog from a prior
	// process is drained without waiting for the first interval.
	w.tick(ctx)
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("email outbox worker stopped")
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

func (w *OutboxWorker) tick(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	n, err := w.repo.ProcessBatch(w.batchSize, w.backoff, func(e *model.OutboundEmail) error {
		return w.deliver.Deliver(e.Recipient, e.Subject, e.BodyHTML)
	})
	if err != nil {
		slog.Error("outbox tick: ProcessBatch failed", "error", err)
		return
	}
	if n > 0 {
		slog.Debug("outbox tick processed rows", "count", n)
	}
}
