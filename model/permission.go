package model

type Permission struct {
	BaseModel
	Name        string  `gorm:"type:varchar(100);uniqueIndex;not null" json:"name"`
	Description *string `gorm:"type:text" json:"description,omitempty"`
}

func (Permission) TableName() string {
	return "permissions"
}

// UserRole is the join table model.
type UserRole struct {
	UserID string `gorm:"primaryKey"`
	RoleID string `gorm:"primaryKey"`
}

func (UserRole) TableName() string {
	return "user_roles"
}

// RolePermission is the join table model. Matches migration 011 — composite
// primary key only, no metadata columns.
type RolePermission struct {
	RoleID       string `gorm:"primaryKey" json:"role_id"`
	PermissionID string `gorm:"primaryKey" json:"permission_id"`
}

func (RolePermission) TableName() string {
	return "role_permissions"
}
