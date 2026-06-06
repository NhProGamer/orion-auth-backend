package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
	"orion-auth-backend/policy/inputs"
)

const ContextOAuthClient = "oauth_client"

// PolicyEvaluator is a narrow interface the ClientAuth middleware uses to
// evaluate client_auth policies. It is satisfied by an adapter on
// policy.Service in main.go — kept here to avoid an import cycle.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, policyType string, input map[string]any) (deny bool, reason string, err error)
}

// ClientAuth authenticates OAuth2 clients using client_secret_basic,
// client_secret_post, client_assertion (private_key_jwt / client_secret_jwt),
// or no auth (public clients).
//
// hmacEncryptionKey is the AES-256 key used to seal per-client HMAC secrets;
// when nil or empty, client_secret_jwt authentication is rejected with a
// clear error (the server has not been configured to decrypt the stored
// HMAC keys).
//
// If evaluator is non-nil, client_auth policies are evaluated after a
// successful credential check. A deny aborts the request with invalid_client.
//
// The clients dependency is the service-layer ClientFinder — the middleware
// never touches the database directly, so it can be unit-tested with a stub.
func ClientAuth(clients ClientFinder, hasher *crypto.Argon2Hasher, tokenEndpoint string, jwksCache *JWKSCache, hmacEncryptionKey []byte, evaluator PolicyEvaluator) gin.HandlerFunc {
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

		// 3. Try client_assertion (private_key_jwt OR client_secret_jwt)
		if clientID == uuid.Nil {
			assertionType := c.PostForm("client_assertion_type")
			assertion := c.PostForm("client_assertion")
			if assertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" && assertion != "" {
				alg, subID, hmacSealed, jwksURI, err := resolveAssertionClient(clients, assertion)
				if err != nil {
					pkg.HandleError(c, pkg.ErrInvalidClient(err.Error()))
					c.Abort()
					return
				}
				var (
					cid    uuid.UUID
					vErr   error
					method string
				)
				switch alg {
				case "HS256":
					if len(hmacEncryptionKey) == 0 {
						pkg.HandleError(c, pkg.ErrInvalidClient("client_secret_jwt is not enabled on this server"))
						c.Abort()
						return
					}
					if len(hmacSealed) == 0 {
						pkg.HandleError(c, pkg.ErrInvalidClient("client has no hmac key configured for client_secret_jwt"))
						c.Abort()
						return
					}
					hmacKey, err := crypto.DecryptHMACSecret(hmacSealed, hmacEncryptionKey)
					if err != nil {
						pkg.HandleError(c, pkg.ErrInvalidClient("failed to recover client hmac key"))
						c.Abort()
						return
					}
					cid, vErr = ValidateClientSecretJWT(assertion, tokenEndpoint, hmacKey)
					method = "client_secret_jwt"
				default:
					if jwksURI == "" {
						pkg.HandleError(c, pkg.ErrInvalidClient("client has no jwks_uri configured for private_key_jwt"))
						c.Abort()
						return
					}
					cid, vErr = ValidateClientAssertionJWT(assertion, tokenEndpoint, jwksURI, jwksCache)
					method = "private_key_jwt"
				}
				if vErr != nil {
					pkg.HandleError(c, pkg.ErrInvalidClient(vErr.Error()))
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
				authMethod = method
			}
		}

		if clientID == uuid.Nil {
			pkg.HandleError(c, pkg.ErrInvalidClient("missing client credentials"))
			c.Abort()
			return
		}

		// Look up client through the service layer (enforces active = TRUE).
		oauthClient, err := clients.FindActive(clientID)
		if err != nil || oauthClient == nil {
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

		// Evaluate client_auth policies (optional)
		if evaluator != nil {
			if authMethod == "" {
				if jwtAuthenticated {
					authMethod = "private_key_jwt"
				} else {
					authMethod = "none"
				}
			}
			pInput := inputs.BuildClientAuthInput(
				oauthClient,
				authMethod,
				c.Request.Method,
				c.Request.URL.Path,
				c.ClientIP(),
				c.GetHeader("User-Agent"),
			)
			deny, reason, err := evaluator.Evaluate(c.Request.Context(), "client_auth", pInput)
			if err == nil && deny {
				pkg.HandleError(c, pkg.ErrInvalidClient(reason))
				c.Abort()
				return
			}
		}

		c.Set(ContextOAuthClient, oauthClient)
		c.Next()
	}
}

// resolveAssertionClient extracts the JWT header alg, the sub claim
// (client_id), and pulls the client's stored credentials needed to verify
// either flavour of client_assertion:
//   - alg HS256 → returns sealed HMAC key (caller decrypts and verifies)
//   - alg RS*/ES*/PS* → returns the client's JWKS URI for remote key fetch
func resolveAssertionClient(clients ClientFinder, assertion string) (alg string, clientID uuid.UUID, hmacSealed []byte, jwksURI string, err error) {
	parts := strings.SplitN(assertion, ".", 3)
	if len(parts) != 3 {
		return "", uuid.Nil, nil, "", errors.New("malformed JWT")
	}
	headerBytes, herr := base64.RawURLEncoding.DecodeString(parts[0])
	if herr != nil {
		return "", uuid.Nil, nil, "", errors.New("malformed JWT header")
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if jerr := json.Unmarshal(headerBytes, &header); jerr != nil {
		return "", uuid.Nil, nil, "", errors.New("invalid JWT header")
	}

	payload, perr := base64.RawURLEncoding.DecodeString(parts[1])
	if perr != nil {
		return "", uuid.Nil, nil, "", errors.New("malformed JWT payload")
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if jerr := json.Unmarshal(payload, &claims); jerr != nil {
		return "", uuid.Nil, nil, "", errors.New("invalid JWT claims")
	}
	cid, perr := uuid.Parse(claims.Sub)
	if perr != nil {
		return "", uuid.Nil, nil, "", errors.New("invalid client_id in sub claim")
	}

	client, ferr := clients.FindActive(cid)
	if ferr != nil || client == nil {
		return "", uuid.Nil, nil, "", errors.New("unknown client")
	}

	jwksURIStr := ""
	if client.JWKSUri != nil {
		jwksURIStr = *client.JWKSUri
	}
	return header.Alg, cid, client.SecretHMACKey, jwksURIStr, nil
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
