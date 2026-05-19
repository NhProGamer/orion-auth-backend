package model

import (
	"github.com/lib/pq"
)

type OAuthClient struct {
	BaseModel
	SecretHash                   *string        `gorm:"type:varchar(255)" json:"-"`
	Name                         string         `gorm:"type:varchar(255);not null" json:"name"`
	Description                  *string        `gorm:"type:text" json:"description,omitempty"`
	RedirectURIs                 pq.StringArray `gorm:"type:text[];default:'{}'" json:"redirect_uris"`
	GrantTypes                   pq.StringArray `gorm:"type:text[];default:'{}'" json:"grant_types"`
	ResponseTypes                pq.StringArray `gorm:"type:text[];default:'{}'" json:"response_types"`
	Scopes                       pq.StringArray `gorm:"type:text[];default:'{}'" json:"scopes"`
	TokenAuthMethod              string         `gorm:"type:varchar(50);default:'client_secret_basic'" json:"token_auth_method"`
	IsPublic                     bool           `gorm:"default:false" json:"is_public"`
	IsFirstParty                 bool           `gorm:"default:false" json:"is_first_party"`
	RequirePKCE                  bool           `gorm:"default:true" json:"require_pkce"`
	JWKSUri                      *string        `gorm:"type:varchar(512)" json:"jwks_uri,omitempty"`
	AccessTokenTTL               int            `gorm:"default:3600" json:"access_token_ttl"`
	RefreshTokenTTL              int            `gorm:"default:86400" json:"refresh_token_ttl"`
	IDTokenTTL                   int            `gorm:"default:3600" json:"id_token_ttl"`
	PostLogoutRedirectURIs       pq.StringArray `gorm:"type:text[];default:'{}'" json:"post_logout_redirect_uris"`
	BackchannelLogoutURI         *string        `gorm:"type:varchar(512)" json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionReq  bool           `gorm:"column:backchannel_logout_session_required;default:false" json:"backchannel_logout_session_required"`
	FrontchannelLogoutURI        *string        `gorm:"type:varchar(512)" json:"frontchannel_logout_uri,omitempty"`
	FrontchannelLogoutSessionReq bool           `gorm:"column:frontchannel_logout_session_required;default:false" json:"frontchannel_logout_session_required"`
	SubjectType                  string         `gorm:"type:varchar(20);default:'public'" json:"subject_type"`
	SectorIdentifierURI          *string        `gorm:"type:varchar(512)" json:"sector_identifier_uri,omitempty"`
	UserinfoSignedResponseAlg    *string        `gorm:"type:varchar(10)" json:"userinfo_signed_response_alg,omitempty"`
	SecretHMACKey                []byte         `gorm:"type:bytea" json:"-"`
	RegistrationAccessTokenHash  *string        `gorm:"type:varchar(64)" json:"-"`
	Active                       bool           `gorm:"default:true" json:"active"`
}

func (OAuthClient) TableName() string {
	return "oauth_clients"
}

func (c *OAuthClient) HasGrantType(grantType string) bool {
	for _, g := range c.GrantTypes {
		if g == grantType {
			return true
		}
	}
	return false
}

func (c *OAuthClient) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func (c *OAuthClient) HasRedirectURI(uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

func (c *OAuthClient) HasPostLogoutRedirectURI(uri string) bool {
	for _, u := range c.PostLogoutRedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

func (c *OAuthClient) ValidateScopes(requested []string) []string {
	if len(requested) == 0 {
		return c.Scopes
	}
	var valid []string
	for _, r := range requested {
		if c.HasScope(r) {
			valid = append(valid, r)
		}
	}
	return valid
}
