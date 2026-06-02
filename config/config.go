package config

import (
	"log/slog"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Auth     AuthConfig     `mapstructure:"auth"`
	Argon2   Argon2Config   `mapstructure:"argon2"`
	CORS     CORSConfig     `mapstructure:"cors"`
	SMTP     SMTPConfig     `mapstructure:"smtp"`
	WebAuthn WebAuthnConfig `mapstructure:"webauthn"`
	Account  AccountConfig  `mapstructure:"account"`
	AuthUI   AuthUIConfig   `mapstructure:"auth_ui"`
	Issuer       string `mapstructure:"issuer"`
	PairwiseSalt string `mapstructure:"pairwise_salt"`
}

// AuthUIConfig points to the AuthUI SPA frontend the backend redirects to
// for interactive flows (federation continuation, link confirmation,
// onboarding). When BaseURL is empty the issuer URL is used (same-origin
// deployment).
type AuthUIConfig struct {
	BaseURL string `mapstructure:"base_url"`
}

type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
	Mode string `mapstructure:"mode"`
}

type DatabaseConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	Name            string        `mapstructure:"name"`
	SSLMode         string        `mapstructure:"sslmode"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

func (d DatabaseConfig) DSN() string {
	return "host=" + d.Host +
		" port=" + strings.Trim(viper.GetString("database.port"), " ") +
		" user=" + d.User +
		" password=" + d.Password +
		" dbname=" + d.Name +
		" sslmode=" + d.SSLMode
}

type AuthConfig struct {
	AccessTokenTTL           time.Duration `mapstructure:"access_token_ttl"`
	RefreshTokenTTL          time.Duration `mapstructure:"refresh_token_ttl"`
	SessionTTL               time.Duration `mapstructure:"session_ttl"`
	AuthCodeTTL              time.Duration `mapstructure:"auth_code_ttl"`
	DeviceCodeTTL            time.Duration `mapstructure:"device_code_ttl"`
	PasswordMinLen           int           `mapstructure:"password_min_length"`
	MaxFailAttempts          int           `mapstructure:"max_failed_attempts"`
	LockoutDuration          time.Duration `mapstructure:"lockout_duration"`
	// HMACSecretEncryptionKey is a base64-encoded 32-byte AES-256 key used to
	// seal per-client HMAC keys (client_secret_jwt). When empty,
	// client_secret_jwt support is disabled with a startup warning.
	HMACSecretEncryptionKey string `mapstructure:"hmac_secret_encryption_key"`

	// DCRInitialAccessToken, when non-empty, gates POST /register behind an
	// operator-issued Bearer token (RFC 7591 §3). Empty leaves the
	// endpoint open — RFC compliant but unsafe in most production
	// deployments. Override at runtime with
	// ORION_AUTH_DCR_INITIAL_ACCESS_TOKEN.
	DCRInitialAccessToken string `mapstructure:"dcr_initial_access_token"`
}

type Argon2Config struct {
	Memory      uint32 `mapstructure:"memory"`
	Iterations  uint32 `mapstructure:"iterations"`
	Parallelism uint8  `mapstructure:"parallelism"`
	SaltLength  uint32 `mapstructure:"salt_length"`
	KeyLength   uint32 `mapstructure:"key_length"`
}

type SMTPConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	From     string `mapstructure:"from"`
	FromName string `mapstructure:"from_name"`
	TLS      bool   `mapstructure:"tls"`
}

type CORSConfig struct {
	AllowedOrigins []string `mapstructure:"allowed_origins"`
	AllowedMethods []string `mapstructure:"allowed_methods"`
	AllowedHeaders []string `mapstructure:"allowed_headers"`
	MaxAge         int      `mapstructure:"max_age"`
}

type WebAuthnConfig struct {
	RPDisplayName string   `mapstructure:"rp_display_name"`
	RPID          string   `mapstructure:"rp_id"`
	RPOrigins     []string `mapstructure:"rp_origins"`
}

type AccountConfig struct {
	ReauthTokenTTL          time.Duration `mapstructure:"reauth_token_ttl"`
	EmailChangeTokenTTL     time.Duration `mapstructure:"email_change_token_ttl"`
	DeletionGracePeriod     time.Duration `mapstructure:"deletion_grace_period"`
	PasskeyChallengeTTL     time.Duration `mapstructure:"passkey_challenge_ttl"`
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/orionauth")

	viper.SetEnvPrefix("ORION")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Sensitive keys that should resolve from env even if the on-disk
	// config.yaml does not declare them. viper.Unmarshal only honours
	// AutomaticEnv for keys it already knows about, so we bind these
	// explicitly to avoid silent fallbacks to the empty string in
	// container deployments that ship without a populated config.yaml.
	for _, key := range []string{
		"auth.hmac_secret_encryption_key",
		"auth.dcr_initial_access_token",
		"database.password",
		"smtp.password",
	} {
		_ = viper.BindEnv(key)
	}

	if err := viper.ReadInConfig(); err != nil {
		slog.Warn("config file not found, using env vars only", "error", err)
	}

	setAccountDefaults()

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func setAccountDefaults() {
	viper.SetDefault("account.reauth_token_ttl", "10m")
	viper.SetDefault("account.email_change_token_ttl", "1h")
	viper.SetDefault("account.deletion_grace_period", "168h") // 7d
	viper.SetDefault("account.passkey_challenge_ttl", "5m")
}
