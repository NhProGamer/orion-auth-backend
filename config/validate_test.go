package config

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// baseRelease returns a Config that passes every Validate check in release
// mode. Each test mutates one field to verify the corresponding error fires.
func baseRelease() Config {
	return Config{
		Server: ServerConfig{Mode: "release"},
		Database: DatabaseConfig{
			Password: "strong-prod-password",
			SSLMode:  "require",
		},
		Auth: AuthConfig{
			HMACSecretEncryptionKey: "ZGV2LWtleS1ub3QtZW1wdHk=",
			ActionTokenSigningKey:   "ZGV2LWtleS1ub3QtZW1wdHk=",
		},
		CORS: CORSConfig{
			AllowedOrigins: []string{"https://app.example.com"},
		},
		SMTP:         SMTPConfig{Host: "smtp.example.com", TLS: true},
		Issuer:       "https://auth.example.com",
		PairwiseSalt: "9d8a7b6c5e4f3a2b1c0d9e8f7a6b5c4d",
	}
}

func TestValidate_AcceptsHealthyReleaseConfig(t *testing.T) {
	cfg := baseRelease()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected nil for healthy config, got %v", err)
	}
}

func TestValidate_ReleaseModeRefusesUnsafeValues(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*Config)
		wantInMsg  string
	}{
		{
			name:      "pairwise_salt sentinel",
			mutate:    func(c *Config) { c.PairwiseSalt = PairwiseSaltSentinel },
			wantInMsg: "pairwise_salt",
		},
		{
			name:      "pairwise_salt empty",
			mutate:    func(c *Config) { c.PairwiseSalt = "" },
			wantInMsg: "pairwise_salt",
		},
		{
			name:      "hmac key empty",
			mutate:    func(c *Config) { c.Auth.HMACSecretEncryptionKey = "" },
			wantInMsg: "hmac_secret_encryption_key",
		},
		{
			name:      "issuer localhost",
			mutate:    func(c *Config) { c.Issuer = "http://localhost:8080" },
			wantInMsg: "issuer",
		},
		{
			name:      "issuer empty",
			mutate:    func(c *Config) { c.Issuer = "" },
			wantInMsg: "issuer",
		},
		{
			name:      "cors wildcard",
			mutate:    func(c *Config) { c.CORS.AllowedOrigins = []string{"*"} },
			wantInMsg: "allowed_origins contains '*'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseRelease()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected error in release mode, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantInMsg) {
				t.Fatalf("error %q does not mention %q", err.Error(), tt.wantInMsg)
			}
		})
	}
}

func TestValidate_DebugModeWarnsButReturnsNil(t *testing.T) {
	cfg := baseRelease()
	cfg.Server.Mode = "debug"
	cfg.PairwiseSalt = PairwiseSaltSentinel
	cfg.Auth.HMACSecretEncryptionKey = ""
	cfg.Database.SSLMode = "disable"

	buf := &bytes.Buffer{}
	restore := swapLogger(t, slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer restore()

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected nil in debug mode, got %v", err)
	}
	logs := buf.String()
	// sslmode=disable is now a permanent soft warning (never blocks);
	// the other two hard-blocks must still surface as debug warnings.
	for _, want := range []string{"pairwise_salt", "hmac_secret_encryption_key", "sslmode=disable"} {
		if !strings.Contains(logs, want) {
			t.Errorf("expected slog output to mention %q; got %s", want, logs)
		}
	}
}

// TestValidate_SSLModeDisableNeverBlocks confirms the relaxation: even
// in release mode, sslmode=disable is a warning only — deployments
// where the DB lives on the same private network (docker-compose,
// k8s pod network, VPC) shouldn't have to bend the rules.
func TestValidate_SSLModeDisableNeverBlocks(t *testing.T) {
	cfg := baseRelease()
	cfg.Database.SSLMode = "disable"

	buf := &bytes.Buffer{}
	restore := swapLogger(t, slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer restore()

	if err := cfg.Validate(); err != nil {
		t.Fatalf("sslmode=disable must not block release boot, got %v", err)
	}
	if !strings.Contains(buf.String(), "sslmode=disable") {
		t.Errorf("expected a soft warning naming sslmode=disable; got %s", buf.String())
	}
}

func TestValidate_SoftWarningsAlwaysEmit(t *testing.T) {
	cfg := baseRelease()
	cfg.Server.Mode = "debug"
	cfg.SMTP = SMTPConfig{Host: "smtp.gmail.com", TLS: false}
	cfg.Database.Password = "orionauth"

	buf := &bytes.Buffer{}
	restore := swapLogger(t, slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer restore()

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	logs := buf.String()
	if !strings.Contains(logs, "SMTP TLS is disabled") {
		t.Errorf("expected SMTP TLS warning, got %s", logs)
	}
	if !strings.Contains(logs, "shipped development default 'orionauth'") {
		t.Errorf("expected default DB password warning, got %s", logs)
	}
}

func TestValidate_AccumulatesMultipleErrors(t *testing.T) {
	cfg := baseRelease()
	cfg.PairwiseSalt = ""
	cfg.Auth.HMACSecretEncryptionKey = ""

	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected error")
	}
	msg := err.Error()
	for _, want := range []string{"pairwise_salt", "hmac_secret_encryption_key"} {
		if !strings.Contains(msg, want) {
			t.Errorf("expected aggregated error to contain %q; got %s", want, msg)
		}
	}
}

// swapLogger redirects the default slog logger for the duration of a test.
// The slog package exposes SetDefault but not Default-getter that captures
// the prior handler; we keep a manual chain so tests are deterministic.
func swapLogger(t *testing.T, l *slog.Logger) func() {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(l)
	return func() { slog.SetDefault(prev) }
}

// silence unused import warnings on context — kept available for future
// tests that need to thread cancellation through Validate.
var _ = context.Background
