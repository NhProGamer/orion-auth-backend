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
	Issuer   string         `mapstructure:"issuer"`
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
	AccessTokenTTL  time.Duration `mapstructure:"access_token_ttl"`
	RefreshTokenTTL time.Duration `mapstructure:"refresh_token_ttl"`
	SessionTTL      time.Duration `mapstructure:"session_ttl"`
	AuthCodeTTL     time.Duration `mapstructure:"auth_code_ttl"`
	DeviceCodeTTL   time.Duration `mapstructure:"device_code_ttl"`
	PasswordMinLen  int           `mapstructure:"password_min_length"`
	MaxFailAttempts int           `mapstructure:"max_failed_attempts"`
	LockoutDuration time.Duration `mapstructure:"lockout_duration"`
}

type Argon2Config struct {
	Memory      uint32 `mapstructure:"memory"`
	Iterations  uint32 `mapstructure:"iterations"`
	Parallelism uint8  `mapstructure:"parallelism"`
	SaltLength  uint32 `mapstructure:"salt_length"`
	KeyLength   uint32 `mapstructure:"key_length"`
}

type CORSConfig struct {
	AllowedOrigins []string `mapstructure:"allowed_origins"`
	AllowedMethods []string `mapstructure:"allowed_methods"`
	AllowedHeaders []string `mapstructure:"allowed_headers"`
	MaxAge         int      `mapstructure:"max_age"`
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/orionauth")

	viper.SetEnvPrefix("ORION")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		slog.Warn("config file not found, using env vars only", "error", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
