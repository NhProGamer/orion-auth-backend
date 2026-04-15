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
