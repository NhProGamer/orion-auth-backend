package oidc

import (
	"github.com/gin-gonic/gin"

	"OrionAuth/middleware"
	"OrionAuth/pkg"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(router *gin.Engine, bearerAuth gin.HandlerFunc) {
	router.GET("/.well-known/openid-configuration", h.Discovery)
	router.GET("/.well-known/jwks.json", h.JWKS)
	router.GET("/userinfo", bearerAuth, h.UserInfo)
	router.POST("/userinfo", bearerAuth, h.UserInfo)
}

func (h *Handler) RegisterAdminRoutes(admin *gin.RouterGroup) {
	admin.GET("/keys", h.ListKeys)
	admin.POST("/keys/rotate", h.RotateKey)
}

func (h *Handler) Discovery(c *gin.Context) {
	pkg.OK(c, h.service.GetDiscovery())
}

func (h *Handler) JWKS(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=3600")
	pkg.OK(c, h.service.GetJWKS())
}

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

func (h *Handler) ListKeys(c *gin.Context) {
	jwks := h.service.GetJWKS()
	pkg.OK(c, gin.H{"keys": jwks.Keys})
}

func (h *Handler) RotateKey(c *gin.Context) {
	if err := h.service.RotateKey(); err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to rotate signing key: "+err.Error()))
		return
	}
	pkg.OK(c, gin.H{"message": "signing key rotated"})
}
