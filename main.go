package main

import (
	"log/slog"
	"os"

	"OrionAuth/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	slog.Info("OrionAuth starting",
		"host", cfg.Server.Host,
		"port", cfg.Server.Port,
		"issuer", cfg.Issuer,
	)
}
