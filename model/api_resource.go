package model

type APIResource struct {
	BaseModel
	Name           string               `gorm:"type:varchar(255);not null" json:"name"`
	Identifier     string               `gorm:"type:varchar(512);uniqueIndex;not null" json:"identifier"`
	Description    *string              `gorm:"type:text" json:"description,omitempty"`
	SigningAlg     string               `gorm:"type:varchar(10);default:'RS256'" json:"signing_alg"`
	AccessTokenTTL int                  `gorm:"default:3600" json:"access_token_ttl"`
	Active         bool                 `gorm:"default:true" json:"active"`
	Permissions    []ResourcePermission `gorm:"foreignKey:ResourceID" json:"permissions,omitempty"`
}

func (APIResource) TableName() string {
	return "api_resources"
}
