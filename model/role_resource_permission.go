package model

import "github.com/google/uuid"

type RoleResourcePermission struct {
	RoleID       uuid.UUID `gorm:"primaryKey" json:"role_id"`
	PermissionID uuid.UUID `gorm:"primaryKey" json:"permission_id"`
}

func (RoleResourcePermission) TableName() string {
	return "role_resource_permissions"
}
