package config

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// PairwiseSaltSentinel is the placeholder value shipped in config.yaml. A
// deployment that boots in release mode with this value still set is
// considered a misconfiguration: every pairwise sub claim would be
// derivable by anyone who reads the published default.
const PairwiseSaltSentinel = "change-me-in-production"

// Validate enforces the production-safety invariants on the loaded
// configuration. In release mode (cfg.Server.Mode == "release") it returns
// an aggregated error listing every unsafe setting; in debug/test mode it
// emits slog warnings without blocking the boot, so developers can iterate
// quickly while still being nudged toward fixing the underlying issue.
//
// Each individual check is also exposed via a helper so tests can pinpoint
// specific failures.
func (c *Config) Validate() error {
	isRelease := strings.EqualFold(c.Server.Mode, "release")

	var releaseErrs []string

	// --- HARD CHECKS: only enforced in release mode ---

	if c.PairwiseSalt == "" || c.PairwiseSalt == PairwiseSaltSentinel {
		msg := "pairwise_salt must be overridden with a strong random value (current value is the shipped placeholder)"
		if isRelease {
			releaseErrs = append(releaseErrs, msg)
		} else {
			slog.Warn("config validation: " + msg + " — UNSAFE for production")
		}
	}

	if c.Auth.HMACSecretEncryptionKey == "" {
		msg := "auth.hmac_secret_encryption_key is empty; federation client_secrets will be stored UNENCRYPTED and client_secret_jwt is disabled"
		if isRelease {
			releaseErrs = append(releaseErrs, msg)
		} else {
			slog.Warn("config validation: " + msg)
		}
	}

	if strings.EqualFold(c.Database.SSLMode, "disable") {
		msg := "database.sslmode=disable is forbidden in release mode; use require or verify-full"
		if isRelease {
			releaseErrs = append(releaseErrs, msg)
		} else {
			slog.Warn("config validation: " + msg)
		}
	}

	if c.Issuer == "" || strings.HasPrefix(c.Issuer, "http://localhost") || strings.HasPrefix(c.Issuer, "http://127.0.0.1") {
		msg := fmt.Sprintf("issuer %q is not safe for release mode; must be an https URL pointing to your public endpoint", c.Issuer)
		if isRelease {
			releaseErrs = append(releaseErrs, msg)
		} else {
			slog.Warn("config validation: " + msg)
		}
	}

	for _, o := range c.CORS.AllowedOrigins {
		if o == "*" {
			msg := "cors.allowed_origins contains '*' which is incompatible with Access-Control-Allow-Credentials: true"
			if isRelease {
				releaseErrs = append(releaseErrs, msg)
			} else {
				slog.Warn("config validation: " + msg)
			}
			break
		}
	}

	// --- SOFT CHECKS: warnings only, never block ---

	if !c.SMTP.TLS && c.SMTP.Host != "" && !isLocalhost(c.SMTP.Host) {
		slog.Warn("config validation: SMTP TLS is disabled with a remote host; verification/reset emails will be sent in plaintext",
			"smtp_host", c.SMTP.Host)
	}

	if c.Database.Password == "orionauth" {
		slog.Warn("config validation: database.password is the shipped development default 'orionauth'; override via ORION_DATABASE_PASSWORD")
	}

	if !isRelease && !strings.EqualFold(c.Server.Mode, "test") && !strings.EqualFold(c.Server.Mode, "debug") {
		slog.Warn("config validation: server.mode is not one of release/debug/test", "mode", c.Server.Mode)
	}

	if len(releaseErrs) == 0 {
		return nil
	}
	return errors.New("config validation failed for release mode:\n  - " + strings.Join(releaseErrs, "\n  - "))
}

func isLocalhost(host string) bool {
	return strings.EqualFold(host, "localhost") || host == "127.0.0.1" || host == "::1"
}
