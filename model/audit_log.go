package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type AuditLog struct {
	ID        uuid.UUID       `gorm:"type:uuid;primaryKey" json:"id"`
	UserID    *uuid.UUID      `gorm:"type:uuid;index" json:"user_id,omitempty"`
	ClientID  *uuid.UUID      `gorm:"type:uuid" json:"client_id,omitempty"`
	Action    string          `gorm:"type:varchar(100);index;not null" json:"action"`
	IPAddress *string         `gorm:"type:inet" json:"ip_address,omitempty"`
	UserAgent *string         `gorm:"type:varchar(512)" json:"user_agent,omitempty"`
	Metadata  json.RawMessage `gorm:"type:jsonb;default:'{}'" json:"metadata,omitempty"`
	CreatedAt time.Time       `gorm:"autoCreateTime;index" json:"created_at"`
}

func (AuditLog) TableName() string {
	return "audit_logs"
}
