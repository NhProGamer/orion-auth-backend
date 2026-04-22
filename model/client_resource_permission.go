package model

import "github.com/google/uuid"

type ClientResourcePermission struct {
	ClientID     uuid.UUID `gorm:"primaryKey" json:"client_id"`
	PermissionID uuid.UUID `gorm:"primaryKey" json:"permission_id"`
}

func (ClientResourcePermission) TableName() string {
	return "client_resource_permissions"
}
