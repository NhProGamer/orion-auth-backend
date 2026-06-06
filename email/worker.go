package email

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"orion-auth-backend/metrics"
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

	// done is closed when Start returns; Stop awaits it. nil until
	// Start runs, so a worker created but never started doesn't
	// block its caller's Stop call.
	doneMu sync.Mutex
	done   chan struct{}
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
// interval. Stop awaits the in-flight tick to finish via a done
// channel; calling Start once and Stop afterwards is the supported
// lifecycle. Concurrent Starts are not supported.
func (w *OutboxWorker) Start(ctx context.Context) {
	slog.Info("email outbox worker started",
		"interval", w.interval, "batch_size", w.batchSize)

	w.doneMu.Lock()
	w.done = make(chan struct{})
	done := w.done
	w.doneMu.Unlock()
	defer close(done)

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

// Stop blocks until the goroutine running Start has returned, or
// until shutdownCtx is cancelled (whichever is first). The caller is
// responsible for cancelling Start's own ctx beforehand — Stop only
// waits, it does not signal. This shape lets main.go cancel the
// worker context, then wait up to 5s for the in-flight ProcessBatch
// transaction to commit before calling srv.Shutdown.
func (w *OutboxWorker) Stop(shutdownCtx context.Context) error {
	w.doneMu.Lock()
	done := w.done
	w.doneMu.Unlock()
	if done == nil {
		// Start was never called; nothing to wait for.
		return nil
	}
	select {
	case <-done:
		return nil
	case <-shutdownCtx.Done():
		slog.Warn("outbox worker did not drain before shutdown deadline")
		return shutdownCtx.Err()
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
	// Publish the current depth even when no rows were touched: a
	// growing queue with zero deliveries is the exact signal alerts
	// need to fire on.
	if depth, err := w.repo.PendingCount(); err != nil {
		slog.Debug("outbox tick: pending count failed", "error", err)
	} else {
		metrics.SetOutboundEmailQueueDepth(float64(depth))
	}
}
