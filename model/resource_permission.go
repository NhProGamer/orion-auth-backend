package model

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ResourcePermission struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	ResourceID  uuid.UUID `gorm:"type:uuid;not null;index" json:"resource_id"`
	Name        string    `gorm:"type:varchar(255);not null" json:"name"`
	Description *string   `gorm:"type:text" json:"description,omitempty"`
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
}

func (ResourcePermission) TableName() string {
	return "resource_permissions"
}

func (r *ResourcePermission) BeforeCreate(_ *gorm.DB) error {
	if r.ID == uuid.Nil {
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		r.ID = id
	}
	return nil
}
