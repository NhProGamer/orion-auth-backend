package password

import (
	"encoding/json"
	"log/slog"
)

const settingKey = "password_policy"

type SettingsRepo interface {
	GetSetting(key string) (string, error)
	SetSetting(key, value string) error
}

type Service struct {
	repo SettingsRepo
}

func NewService(repo SettingsRepo) *Service {
	return &Service{repo: repo}
}

// Get returns the policy persisted under settings.password_policy.
// On any error (missing row, corrupted JSON, DB hiccup) it falls back to
// DefaultPolicy so the system never locks users out of their own auth.
func (s *Service) Get() Policy {
	raw, err := s.repo.GetSetting(settingKey)
	if err != nil {
		slog.Warn("password policy read failed, using default", "error", err)
		return DefaultPolicy()
	}
	if raw == "" {
		return DefaultPolicy()
	}
	var p Policy
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		slog.Warn("password policy json invalid, using default", "error", err)
		return DefaultPolicy()
	}
	return p.Normalize()
}

func (s *Service) Update(p Policy) error {
	p = p.Normalize()
	buf, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return s.repo.SetSetting(settingKey, string(buf))
}
