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

	tables := []struct {
		name  string
		query string
		args  []any
	}{
		{"access_tokens", "expires_at < ? OR (revoked = TRUE AND updated_at < ?)", []any{now, grace}},
		{"refresh_tokens", "expires_at < ? OR (revoked = TRUE AND updated_at < ?)", []any{now, grace}},
		{"authorization_codes", "expires_at < ?", []any{now}},
		{"device_codes", "expires_at < ?", []any{now}},
		{"sessions", "expires_at < ? OR (revoked = TRUE AND updated_at < ?)", []any{now, grace}},
	}

	for _, t := range tables {
		result := db.Exec("DELETE FROM "+t.name+" WHERE "+t.query, t.args...)
		if result.Error != nil {
			slog.Error("cleanup failed", "table", t.name, "error", result.Error)
			continue
		}
		if result.RowsAffected > 0 {
			slog.Info("cleanup completed", "table", t.name, "deleted", result.RowsAffected)
		}
	}
}
