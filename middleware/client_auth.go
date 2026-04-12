package middleware

import (
	"encoding/base64"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"OrionAuth/crypto"
	"OrionAuth/model"
	"OrionAuth/pkg"
)

const ContextOAuthClient = "oauth_client"

// ClientAuth authenticates OAuth2 clients using client_secret_basic,
// client_secret_post, or no auth (public clients).
func ClientAuth(db *gorm.DB, hasher *crypto.Argon2Hasher) gin.HandlerFunc {
	return func(c *gin.Context) {
		var clientID uuid.UUID
		var clientSecret string
		var authMethod string

		// 1. Try client_secret_basic (Authorization: Basic base64(id:secret))
		if authHeader := c.GetHeader("Authorization"); strings.HasPrefix(authHeader, "Basic ") {
			decoded, err := base64.StdEncoding.DecodeString(authHeader[6:])
			if err != nil {
				pkg.HandleError(c, pkg.ErrInvalidClient("malformed basic auth header"))
				c.Abort()
				return
			}
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) != 2 {
				pkg.HandleError(c, pkg.ErrInvalidClient("malformed basic auth credentials"))
				c.Abort()
				return
			}
			id, err := uuid.Parse(parts[0])
			if err != nil {
				pkg.HandleError(c, pkg.ErrInvalidClient("invalid client_id"))
				c.Abort()
				return
			}
			clientID = id
			clientSecret = parts[1]
			authMethod = "client_secret_basic"
		}

		// 2. Try client_secret_post (client_id + client_secret in POST body)
		if clientID == uuid.Nil {
			if idStr := c.PostForm("client_id"); idStr != "" {
				id, err := uuid.Parse(idStr)
				if err != nil {
					pkg.HandleError(c, pkg.ErrInvalidClient("invalid client_id"))
					c.Abort()
					return
				}
				clientID = id
				clientSecret = c.PostForm("client_secret")
				if clientSecret != "" {
					authMethod = "client_secret_post"
				} else {
					authMethod = "none"
				}
			}
		}

		if clientID == uuid.Nil {
			pkg.HandleError(c, pkg.ErrInvalidClient("missing client credentials"))
			c.Abort()
			return
		}

		// Look up client
		var oauthClient model.OAuthClient
		err := db.Where("id = ? AND active = TRUE", clientID).First(&oauthClient).Error
		if err != nil {
			pkg.HandleError(c, pkg.ErrInvalidClient("unknown client"))
			c.Abort()
			return
		}

		// Validate auth method matches client configuration
		if oauthClient.IsPublic {
			if authMethod != "none" && clientSecret != "" {
				// Public client should not send secret, but we tolerate it
			}
		} else {
			// Confidential client must authenticate
			if clientSecret == "" {
				pkg.HandleError(c, pkg.ErrInvalidClient("client authentication required"))
				c.Abort()
				return
			}
			if oauthClient.SecretHash == nil {
				pkg.HandleError(c, pkg.ErrInvalidClient("client has no secret configured"))
				c.Abort()
				return
			}

			match, err := hasher.Verify(clientSecret, *oauthClient.SecretHash)
			if err != nil || !match {
				pkg.HandleError(c, pkg.ErrInvalidClient("invalid client credentials"))
				c.Abort()
				return
			}
		}

		c.Set(ContextOAuthClient, &oauthClient)
		c.Next()
	}
}

// GetOAuthClient extracts the authenticated OAuth2 client from context.
func GetOAuthClient(c *gin.Context) (*model.OAuthClient, bool) {
	val, exists := c.Get(ContextOAuthClient)
	if !exists {
		return nil, false
	}
	client, ok := val.(*model.OAuthClient)
	return client, ok
}
