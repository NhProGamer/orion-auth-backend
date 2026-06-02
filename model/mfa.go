package model

import (
	"github.com/google/uuid"
	"github.com/lib/pq"
)

type MFAMethod struct {
	BaseModel
	UserID      uuid.UUID      `gorm:"type:uuid;index;not null" json:"user_id"`
	Type        string         `gorm:"type:varchar(20);default:'totp'" json:"type"`
	Secret      string         `gorm:"type:varchar(255);not null" json:"-"`
	Verified    bool           `gorm:"default:false" json:"verified"`
	BackupCodes pq.StringArray `gorm:"type:text[];default:'{}'" json:"-"`
	// LastUsedTOTPStep is the TOTP step number (Unix time / period) of the
	// most recently validated code. ValidateCode refuses any subsequent
	// code whose step is <= this value, preventing intra-window replay
	// (Vuln 12).
	LastUsedTOTPStep int64 `gorm:"default:0;not null" json:"-"`
}

func (MFAMethod) TableName() string {
	return "mfa_methods"
}
