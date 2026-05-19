package model

import "time"

// RevokedJTI is an entry in the JWT access token denylist (RFC 9068).
// A row is created when /revoke succeeds against a JWT access token and is
// consulted by /introspect to flip Active to false. Entries are purged when
// expires_at < NOW(); the TTL ensures the table stays bounded by the
// configured access token TTL.
type RevokedJTI struct {
	JTI       string    `gorm:"type:varchar(255);primaryKey" json:"-"`
	ExpiresAt time.Time `gorm:"index;not null" json:"-"`
	CreatedAt time.Time `gorm:"autoCreateTime" json:"-"`
}

func (RevokedJTI) TableName() string {
	return "revoked_jtis"
}
