package oauth

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"OrionAuth/middleware"
	"OrionAuth/model"
	"OrionAuth/pkg"
)

type Handler struct {
	service *Service
	issuer  string
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(router *gin.Engine, clientAuth gin.HandlerFunc, issuer string) {
	h.issuer = issuer

	// Authorization endpoints (no client auth middleware, client is identified by params)
	router.GET("/authorize", h.Authorize)
	router.POST("/authorize/login", h.AuthorizeLogin)
	router.POST("/authorize/consent", h.AuthorizeConsent)

	// Token endpoint (client auth required)
	router.POST("/token", clientAuth, h.Token)

	// Introspection and revocation (client auth required)
	router.POST("/introspect", clientAuth, h.Introspect)
	router.POST("/revoke", clientAuth, h.Revoke)
}

// Authorize initiates the authorization request (API-driven).
func (h *Handler) Authorize(c *gin.Context) {
	clientID := c.Query("client_id")
	if clientID == "" {
		pkg.HandleError(c, pkg.ErrInvalidRequest("missing client_id"))
		return
	}

	// Look up client from DB via service's repo
	client, err := h.service.repo.findClient(clientID)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	resp, err := h.service.InitAuthorize(
		client,
		c.Query("redirect_uri"),
		c.Query("response_type"),
		c.Query("scope"),
		c.Query("state"),
		c.Query("nonce"),
		c.Query("code_challenge"),
		c.Query("code_challenge_method"),
	)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, resp)
}

// AuthorizeLogin handles the login step of the authorize flow.
func (h *Handler) AuthorizeLogin(c *gin.Context) {
	var input AuthorizeLoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrInvalidRequest("invalid request body: "+err.Error()))
		return
	}

	resp, err := h.service.AuthorizeLogin(input, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	// If no consent needed, auto-complete and return the code
	if !resp.RequiresConsent {
		codeResp, err := h.service.CompleteAuthorizeFirstParty(resp.RequestID, c.ClientIP(), c.GetHeader("User-Agent"))
		if err != nil {
			pkg.HandleError(c, err)
			return
		}
		c.JSON(http.StatusOK, codeResp)
		return
	}

	pkg.OK(c, resp)
}

// AuthorizeConsent handles the consent step.
func (h *Handler) AuthorizeConsent(c *gin.Context) {
	var input AuthorizeConsentInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrInvalidRequest("invalid request body: "+err.Error()))
		return
	}

	resp, err := h.service.AuthorizeConsent(input, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, resp)
}

// Token handles the POST /token endpoint for all grant types.
func (h *Handler) Token(c *gin.Context) {
	client, ok := middleware.GetOAuthClient(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrInvalidClient("client authentication failed"))
		return
	}

	grantType := c.PostForm("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(c, client)
	case "client_credentials":
		h.handleClientCredentialsGrant(c, client)
	case "refresh_token":
		h.handleRefreshTokenGrant(c, client)
	default:
		pkg.HandleError(c, pkg.ErrUnsupportedGrantType("unsupported grant_type: "+grantType))
	}
}

func (h *Handler) handleAuthorizationCodeGrant(c *gin.Context, client *model.OAuthClient) {
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	codeVerifier := c.PostForm("code_verifier")

	if code == "" {
		pkg.HandleError(c, pkg.ErrInvalidRequest("missing code"))
		return
	}
	if redirectURI == "" {
		pkg.HandleError(c, pkg.ErrInvalidRequest("missing redirect_uri"))
		return
	}

	resp, err := h.service.ExchangeAuthorizationCode(client, code, redirectURI, codeVerifier)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, resp)
}

func (h *Handler) handleClientCredentialsGrant(c *gin.Context, client *model.OAuthClient) {
	scope := c.PostForm("scope")

	resp, err := h.service.ExchangeClientCredentials(client, scope)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, resp)
}

func (h *Handler) handleRefreshTokenGrant(c *gin.Context, client *model.OAuthClient) {
	refreshToken := c.PostForm("refresh_token")
	scope := c.PostForm("scope")

	if refreshToken == "" {
		pkg.HandleError(c, pkg.ErrInvalidRequest("missing refresh_token"))
		return
	}

	resp, err := h.service.ExchangeRefreshToken(client, refreshToken, scope)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, resp)
}

// Introspect handles POST /introspect (RFC 7662).
func (h *Handler) Introspect(c *gin.Context) {
	_, ok := middleware.GetOAuthClient(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrInvalidClient("client authentication required"))
		return
	}

	token := c.PostForm("token")
	tokenTypeHint := c.PostForm("token_type_hint")

	resp, err := h.service.Introspect(token, tokenTypeHint, h.issuer)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, resp)
}

// Revoke handles POST /revoke (RFC 7009).
func (h *Handler) Revoke(c *gin.Context) {
	client, ok := middleware.GetOAuthClient(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrInvalidClient("client authentication required"))
		return
	}

	token := c.PostForm("token")
	tokenTypeHint := c.PostForm("token_type_hint")

	if err := h.service.Revoke(token, tokenTypeHint, client); err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{})
}
