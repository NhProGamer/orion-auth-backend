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
