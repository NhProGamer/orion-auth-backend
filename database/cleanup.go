package database

import (
	"log/slog"
	"sync"
	"time"

	"gorm.io/gorm"
)

// CleanupFn runs a single cleanup pass against the database. Returns
// the number of rows deleted (logged when > 0) and any error.
type CleanupFn func(db *gorm.DB, now time.Time) (int64, error)

var (
	cleanupMu  sync.RWMutex
	registered []registeredCleanup
)

type registeredCleanup struct {
	label string
	fn    CleanupFn
}

// RegisterCleanup adds a cleanup function to the periodic sweep run
// by StartCleanupJob. Designed to be called from package init() or
// from a wiring helper at startup so each domain owns its retention
// policy without editing this file. Safe to call concurrently.
//
//	func init() {
//	    database.RegisterCleanup("outbound_emails", func(db *gorm.DB, now time.Time) (int64, error) {
//	        r := db.Exec(`DELETE FROM outbound_emails
//	                       WHERE status IN ('sent','failed') AND created_at < ?`,
//	            now.Add(-7*24*time.Hour))
//	        return r.RowsAffected, r.Error
//	    })
//	}
func RegisterCleanup(label string, fn CleanupFn) {
	cleanupMu.Lock()
	defer cleanupMu.Unlock()
	registered = append(registered, registeredCleanup{label: label, fn: fn})
}

// StartCleanupJob runs a background goroutine that periodically
// deletes expired rows. Currently a fixed interval; future enhancement
// would let each RegisterCleanup declare its own cadence.
func StartCleanupJob(db *gorm.DB, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			runCleanup(db)
		}
	}()
	slog.Info("database cleanup job started", "interval", interval)
}

func runCleanup(db *gorm.DB) {
	now := time.Now()

	// Builtin cleanups for tables owned by the core schema. New tables
	// should prefer RegisterCleanup from their own package over adding
	// to this list — the registry call has no central-file edit cost.
	for _, c := range builtinCleanups(now) {
		execCleanup(db, c.label, c.sql, c.args)
	}

	cleanupMu.RLock()
	regs := append([]registeredCleanup(nil), registered...)
	cleanupMu.RUnlock()
	for _, r := range regs {
		deleted, err := r.fn(db, now)
		if err != nil {
			slog.Error("cleanup failed", "table", r.label, "error", err)
			continue
		}
		if deleted > 0 {
			slog.Info("cleanup completed", "table", r.label, "deleted", deleted)
		}
	}
}

type rawCleanup struct {
	label string
	sql   string
	args  []any
}

func builtinCleanups(now time.Time) []rawCleanup {
	grace := now.Add(-24 * time.Hour)
	return []rawCleanup{
		{"access_tokens", "DELETE FROM access_tokens WHERE expires_at < ? OR (revoked = TRUE AND created_at < ?)", []any{now, grace}},
		{"refresh_tokens", "DELETE FROM refresh_tokens WHERE expires_at < ? OR (revoked = TRUE AND created_at < ?)", []any{now, grace}},
		{"authorization_codes", "DELETE FROM authorization_codes WHERE expires_at < ?", []any{now}},
		{"device_codes", "DELETE FROM device_codes WHERE expires_at < ?", []any{now}},
		{"sessions", "DELETE FROM sessions WHERE expires_at < ? OR (revoked = TRUE AND revoked_at < ?)", []any{now, grace}},
		{"reauth_tokens", "DELETE FROM reauth_tokens WHERE expires_at < ? OR (used = TRUE AND used_at < ?)", []any{now, grace}},
		{"passkey_challenges", "DELETE FROM passkey_challenges WHERE expires_at < ?", []any{now}},
		{"federation_auth_requests", "DELETE FROM federation_auth_requests WHERE expires_at < ?", []any{now}},
		{"federation_pending_links", "DELETE FROM federation_pending_links WHERE expires_at < ?", []any{now}},
		{"federation_pending_signups", "DELETE FROM federation_pending_signups WHERE expires_at < ?", []any{now}},
		// RFC 9068 denylist: drop JTI entries whose underlying JWT has
		// already expired (they can no longer pass signature validation
		// anyway).
		{"revoked_jtis", "DELETE FROM revoked_jtis WHERE expires_at < ?", []any{now}},
		// Hard-delete users whose grace period has elapsed.
		{"users_purged", "DELETE FROM users WHERE deletion_purge_after IS NOT NULL AND deletion_purge_after < ?", []any{now}},
		// Outbox retention: keep sent/failed rows for 7 days for
		// forensics, then drop. Pending rows are never purged here;
		// MaxAttempts controls when they stop retrying.
		{"outbound_emails_purged", "DELETE FROM outbound_emails WHERE status IN ('sent','failed') AND created_at < ?", []any{now.Add(-7 * 24 * time.Hour)}},
	}
}

func execCleanup(db *gorm.DB, label, sql string, args []any) {
	result := db.Exec(sql, args...)
	if result.Error != nil {
		slog.Error("cleanup failed", "table", label, "error", result.Error)
		return
	}
	if result.RowsAffected > 0 {
		slog.Info("cleanup completed", "table", label, "deleted", result.RowsAffected)
	}
}
