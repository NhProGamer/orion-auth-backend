package oidc

import (
	"github.com/gin-gonic/gin"

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
	router.GET("/.well-known/jwks.json", h.JWKS)
	router.GET("/userinfo", rateLimiter, bearerAuth, h.UserInfo)
	router.POST("/userinfo", rateLimiter, bearerAuth, h.UserInfo)
	router.GET("/end_session", h.EndSession)
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

	scopes := middleware.GetScopes(c)

	claims, err := h.service.GetUserInfo(userID, scopes)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, claims)
}

// EndSession handles RP-Initiated Logout (OIDC RP-Initiated Logout 1.0).
// @Summary End session / logout
// @Tags OIDC
// @Produce json
// @Param id_token_hint query string false "Previously issued ID Token"
// @Param post_logout_redirect_uri query string false "URL to redirect after logout"
// @Param state query string false "Opaque value for the RP"
// @Param client_id query string false "Client ID"
// @Success 200 {object} map[string]any
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

	pkg.OK(c, resp)
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
	pkg.OK(c, gin.H{"keys": jwks.Keys})
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
