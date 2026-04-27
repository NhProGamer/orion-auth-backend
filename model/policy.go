package model

const (
	PolicyTypeTokenIssuance = "token_issuance"
	PolicyTypeLogin         = "login"
	PolicyTypeClientAuth    = "client_auth"
	PolicyTypeAdminAPI      = "admin_api"
	PolicyTypeConsent       = "consent"
	PolicyTypeRefresh       = "refresh"
	PolicyTypeIntrospect     = "introspect"
	PolicyTypeDeviceApproval = "device_approval"
	PolicyTypeMFA            = "mfa"
	PolicyTypeCustom         = "custom"
)

type Policy struct {
	BaseModel
	Name        string  `gorm:"type:varchar(255);uniqueIndex;not null" json:"name"`
	Description *string `gorm:"type:text" json:"description,omitempty"`
	Type        string  `gorm:"type:varchar(50);not null" json:"type"`
	Rego        string  `gorm:"type:text;not null" json:"rego"`
	Version     int     `gorm:"default:1;not null" json:"version"`
	Active      bool    `gorm:"default:true;not null" json:"active"`
	Priority    int     `gorm:"default:0;not null" json:"priority"`
}

func (Policy) TableName() string {
	return "policies"
}
