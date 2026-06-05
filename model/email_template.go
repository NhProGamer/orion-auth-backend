package model

import (
	"time"

	"github.com/google/uuid"
)

// EmailTemplate is an admin override for a transactional template.
// When no row exists for a given Name, the embed.FS default applies
// (see email/resolver.go). The Name is one of the fixed set declared
// in email/resolver.go's TemplateNames().
type EmailTemplate struct {
	Name      string     `gorm:"primaryKey;type:varchar(64)" json:"name"`
	Subject   string     `gorm:"not null" json:"subject"`
	BodyHTML  string     `gorm:"column:body_html;not null" json:"body_html"`
	UpdatedAt time.Time  `gorm:"autoUpdateTime" json:"updated_at"`
	UpdatedBy *uuid.UUID `gorm:"type:uuid" json:"updated_by,omitempty"`
}

func (EmailTemplate) TableName() string { return "email_templates" }
