package model

type Role struct {
	BaseModel
	Name        string       `gorm:"type:varchar(100);uniqueIndex;not null" json:"name"`
	Description *string      `gorm:"type:text" json:"description,omitempty"`
	Permissions []Permission `gorm:"many2many:role_permissions;" json:"permissions,omitempty"`
}

func (Role) TableName() string {
	return "roles"
}
