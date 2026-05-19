package model

// TokenFormatOpaque keeps the legacy random 32-byte access token, hashed
// SHA-256 server-side. TokenFormatJWT emits a signed JWT (RFC 9068).
const (
	TokenFormatOpaque = "opaque"
	TokenFormatJWT    = "jwt"
)

type APIResource struct {
	BaseModel
	Name           string               `gorm:"type:varchar(255);not null" json:"name"`
	Identifier     string               `gorm:"type:varchar(512);uniqueIndex;not null" json:"identifier"`
	Description    *string              `gorm:"type:text" json:"description,omitempty"`
	SigningAlg     string               `gorm:"type:varchar(10);default:'RS256'" json:"signing_alg"`
	TokenFormat    string               `gorm:"type:varchar(10);default:'opaque';not null" json:"token_format"`
	AccessTokenTTL int                  `gorm:"default:3600" json:"access_token_ttl"`
	Active         bool                 `gorm:"default:true" json:"active"`
	Permissions    []ResourcePermission `gorm:"foreignKey:ResourceID" json:"permissions,omitempty"`
}

// EmitsJWTAccessTokens reports whether this resource asks the server to
// hand out JWT (RFC 9068) access tokens rather than opaque tokens.
func (r *APIResource) EmitsJWTAccessTokens() bool {
	return r.TokenFormat == TokenFormatJWT
}

func (APIResource) TableName() string {
	return "api_resources"
}
