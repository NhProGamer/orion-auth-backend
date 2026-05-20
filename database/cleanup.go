package database

import (
	"log/slog"
	"time"

	"gorm.io/gorm"
)

// StartCleanupJob runs a background goroutine that periodically deletes
// expired tokens, codes, and sessions from the database.
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
	grace := now.Add(-24 * time.Hour)

	queries := []struct {
		label string
		sql   string
		args  []any
	}{
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
	}

	for _, q := range queries {
		result := db.Exec(q.sql, q.args...)
		if result.Error != nil {
			slog.Error("cleanup failed", "table", q.label, "error", result.Error)
			continue
		}
		if result.RowsAffected > 0 {
			slog.Info("cleanup completed", "table", q.label, "deleted", result.RowsAffected)
		}
	}
}
