package middleware

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
)

const ContextOAuthClient = "oauth_client"

// ClientAuth authenticates OAuth2 clients using client_secret_basic,
// client_secret_post, client_assertion (private_key_jwt / client_secret_jwt),
// or no auth (public clients).
func ClientAuth(db *gorm.DB, hasher *crypto.Argon2Hasher, tokenEndpoint string, jwksCache *JWKSCache) gin.HandlerFunc {
	return func(c *gin.Context) {
		var clientID uuid.UUID
		var clientSecret string
		var authMethod string
		var jwtAuthenticated bool

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

		// 3. Try client_assertion (private_key_jwt)
		if clientID == uuid.Nil {
			assertionType := c.PostForm("client_assertion_type")
			assertion := c.PostForm("client_assertion")
			if assertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" && assertion != "" {
				// Pre-parse to get sub (client_id) for JWKS URI lookup
				subID, jwksURI, err := resolveAssertionClient(db, assertion)
				if err != nil {
					pkg.HandleError(c, pkg.ErrInvalidClient(err.Error()))
					c.Abort()
					return
				}
				cid, err := ValidateClientAssertionJWT(assertion, tokenEndpoint, jwksURI, jwksCache)
				if err != nil {
					pkg.HandleError(c, pkg.ErrInvalidClient(err.Error()))
					c.Abort()
					return
				}
				if cid != subID {
					pkg.HandleError(c, pkg.ErrInvalidClient("client_id mismatch"))
					c.Abort()
					return
				}
				clientID = cid
				jwtAuthenticated = true
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
		if jwtAuthenticated {
			// JWT-based auth is already validated
		} else if oauthClient.IsPublic {
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

// resolveAssertionClient extracts the client_id from a JWT assertion's sub claim
// and looks up the client's JWKS URI for signature verification.
func resolveAssertionClient(db *gorm.DB, assertion string) (uuid.UUID, string, error) {
	parts := strings.SplitN(assertion, ".", 3)
	if len(parts) != 3 {
		return uuid.Nil, "", errors.New("malformed JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return uuid.Nil, "", errors.New("malformed JWT payload")
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return uuid.Nil, "", errors.New("invalid JWT claims")
	}
	clientID, err := uuid.Parse(claims.Sub)
	if err != nil {
		return uuid.Nil, "", errors.New("invalid client_id in sub claim")
	}

	var client model.OAuthClient
	if err := db.Where("id = ? AND active = TRUE", clientID).First(&client).Error; err != nil {
		return uuid.Nil, "", errors.New("unknown client")
	}
	if client.JWKSUri == nil || *client.JWKSUri == "" {
		return uuid.Nil, "", errors.New("client has no jwks_uri configured for private_key_jwt")
	}
	return clientID, *client.JWKSUri, nil
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
