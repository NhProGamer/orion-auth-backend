package model

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type DeviceCode struct {
	DeviceCodeHash string         `gorm:"type:varchar(64);primaryKey" json:"-"`
	UserCode       string         `gorm:"type:varchar(9);uniqueIndex;not null" json:"user_code"`
	ClientID       uuid.UUID      `gorm:"type:uuid;not null" json:"client_id"`
	Scopes         pq.StringArray `gorm:"type:text[];default:'{}'" json:"scopes"`
	UserID         *uuid.UUID     `gorm:"type:uuid" json:"user_id,omitempty"`
	SessionID      *uuid.UUID     `gorm:"type:uuid" json:"session_id,omitempty"`
	Audience       *string        `gorm:"type:varchar(512)" json:"audience,omitempty"`
	Status         string         `gorm:"type:varchar(20);default:'pending'" json:"status"`
	IntervalSecs   int            `gorm:"column:interval_secs;default:5" json:"interval"`
	ExpiresAt      time.Time      `gorm:"index;not null" json:"expires_at"`
	LastPolledAt   *time.Time     `json:"-"`
	CreatedAt      time.Time      `gorm:"autoCreateTime" json:"created_at"`
}

func (DeviceCode) TableName() string {
	return "device_codes"
}

func (d *DeviceCode) IsExpired() bool {
	return d.ExpiresAt.Before(time.Now())
}

func (d *DeviceCode) IsPending() bool {
	return d.Status == "pending"
}
