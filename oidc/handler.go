package oidc

import (
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/middleware"
	"orion-auth-backend/pkg"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(router *gin.Engine, bearerAuth, rateLimiter gin.HandlerFunc) {
	router.GET("/.well-known/openid-configuration", h.Discovery)
	router.GET("/.well-known/oauth-authorization-server", h.OAuthDiscovery)
	router.GET("/.well-known/jwks.json", h.JWKS)
	router.GET("/userinfo", rateLimiter, bearerAuth, h.UserInfo)
	router.POST("/userinfo", rateLimiter, bearerAuth, h.UserInfo)
	router.GET("/end_session", h.EndSession)
	router.GET("/check_session", h.CheckSession)
}

func (h *Handler) RegisterAdminRoutes(admin *gin.RouterGroup) {
	admin.GET("/keys", h.ListKeys)
	admin.POST("/keys/rotate", h.RotateKey)
}

// Discovery returns the OpenID Connect discovery document.
// @Summary Get OpenID Connect discovery configuration
// @Tags OIDC
// @Produce json
// @Success 200 {object} map[string]any
// @Router /.well-known/openid-configuration [get]
func (h *Handler) Discovery(c *gin.Context) {
	pkg.OK(c, h.service.GetDiscovery())
}

// OAuthDiscovery returns the RFC 8414 OAuth 2.0 authorization server metadata.
// @Summary Get OAuth 2.0 authorization server metadata (RFC 8414)
// @Tags OAuth2
// @Produce json
// @Success 200 {object} map[string]any
// @Router /.well-known/oauth-authorization-server [get]
func (h *Handler) OAuthDiscovery(c *gin.Context) {
	pkg.OK(c, h.service.GetOAuthAuthorizationServerMetadata())
}

// JWKS returns the JSON Web Key Set.
// @Summary Get JSON Web Key Set
// @Tags OIDC
// @Produce json
// @Success 200 {object} map[string]any
// @Router /.well-known/jwks.json [get]
func (h *Handler) JWKS(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=3600")
	pkg.OK(c, h.service.GetJWKS())
}

// UserInfo returns claims about the authenticated user.
// @Summary Get user info claims
// @Tags OIDC
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]any
// @Failure 401 {object} map[string]any
// @Router /userinfo [get]
func (h *Handler) UserInfo(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}

	clientID, _ := middleware.GetClientID(c)
	scopes := middleware.GetScopes(c)

	claims, err := h.service.GetUserInfo(userID, clientID, scopes)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	// Determine response shape from client config:
	// - encrypted (JWE wrapping a JWS): when *_alg and *_enc are set
	// - signed (JWS): when only userinfo_signed_response_alg is set
	// - plain JSON: default
	if clientID != uuid.Nil && h.service.clientFinder != nil {
		client, err := h.service.clientFinder.FindActiveByID(clientID)
		if err == nil && client != nil {
			needsSign := client.UserinfoSignedResponseAlg != nil && *client.UserinfoSignedResponseAlg != ""
			needsEnc := client.UserinfoEncryptedResponseAlg != nil && *client.UserinfoEncryptedResponseAlg != "" &&
				client.UserinfoEncryptedResponseEnc != nil && *client.UserinfoEncryptedResponseEnc != ""

			if needsSign || needsEnc {
				jwtStr, err := h.service.GenerateUserInfoJWT(claims, clientID)
				if err != nil {
					pkg.HandleError(c, err)
					return
				}
				if needsEnc {
					if client.JWKSUri == nil || *client.JWKSUri == "" {
						pkg.HandleError(c, pkg.ErrInternal("client requests encrypted userinfo but has no jwks_uri"))
						return
					}
					encrypted, err := h.service.EncryptForClient([]byte(jwtStr), *client.JWKSUri,
						*client.UserinfoEncryptedResponseAlg, *client.UserinfoEncryptedResponseEnc)
					if err != nil {
						pkg.HandleError(c, pkg.ErrInternal("failed to encrypt userinfo: "+err.Error()))
						return
					}
					c.Data(200, "application/jwt", []byte(encrypted))
					return
				}
				c.Data(200, "application/jwt", []byte(jwtStr))
				return
			}
		}
	}

	pkg.OK(c, claims)
}

// EndSession handles RP-Initiated Logout (OIDC RP-Initiated Logout 1.0).
// Performs session revocation and back-channel logout dispatch, then redirects
// the user agent to the AuthUI logout page where front-channel iframes are
// rendered and the user is offered a "return to app" link if a valid
// post_logout_redirect_uri was provided.
// @Summary End session / logout
// @Tags OIDC
// @Param id_token_hint query string false "Previously issued ID Token"
// @Param post_logout_redirect_uri query string false "URL to redirect after logout"
// @Param state query string false "Opaque value for the RP"
// @Param client_id query string false "Client ID"
// @Success 302 "Redirect to AuthUI logout page"
// @Router /end_session [get]
func (h *Handler) EndSession(c *gin.Context) {
	resp, err := h.service.EndSession(EndSessionParams{
		IDTokenHint:           c.Query("id_token_hint"),
		PostLogoutRedirectURI: c.Query("post_logout_redirect_uri"),
		State:                 c.Query("state"),
		ClientID:              c.Query("client_id"),
	})
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	q := url.Values{}
	if resp.RedirectURI != "" {
		q.Set("redirect_uri", resp.RedirectURI)
	}
	for _, uri := range resp.FrontchannelLogoutURIs {
		q.Add("frontchannel_logout_uris", uri)
	}

	target := "/ui/logout"
	if encoded := q.Encode(); encoded != "" {
		target += "?" + encoded
	}
	c.Redirect(http.StatusFound, target)
}

// ListKeys returns all signing keys.
// @Summary List signing keys
// @Tags Admin - Keys
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]any
// @Failure 401 {object} map[string]any
// @Router /api/v1/admin/keys [get]
func (h *Handler) ListKeys(c *gin.Context) {
	jwks := h.service.GetJWKS()
	pkg.List(c, jwks.Keys, len(jwks.Keys))
}

// RotateKey generates a new signing key.
// @Summary Rotate the signing key
// @Tags Admin - Keys
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]any
// @Failure 401 {object} map[string]any
// @Failure 500 {object} map[string]any
// @Router /api/v1/admin/keys/rotate [post]
func (h *Handler) RotateKey(c *gin.Context) {
	if err := h.service.RotateKey(); err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to rotate signing key: "+err.Error()))
		return
	}
	pkg.OK(c, gin.H{"message": "signing key rotated"})
}

// CheckSession serves the OIDC Session Management check_session_iframe HTML page.
func (h *Handler) CheckSession(c *gin.Context) {
	html := `<!DOCTYPE html>
<html><head><title>Check Session</title></head>
<body>
<script>
window.addEventListener("message", function(e) {
  var clientId = e.data.split(" ")[0];
  var sessionState = e.data.split(" ")[1];
  // Compare with cookie-based session state
  var cookie = document.cookie.match(/orionauth_session_state=([^;]*)/);
  var status = "changed";
  if (cookie && cookie[1] === sessionState) {
    status = "unchanged";
  }
  e.source.postMessage(status, e.origin);
});
</script>
</body></html>`
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}
