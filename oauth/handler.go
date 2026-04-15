package oauth

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"orion-auth-backend/audit"
	"orion-auth-backend/middleware"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
	"orion-auth-backend/user"
)

type Handler struct {
	service      *Service
	issuer       string
	auditService *audit.Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) SetAuditService(s *audit.Service) {
	h.auditService = s
}

func (h *Handler) RegisterRoutes(router *gin.Engine, clientAuth gin.HandlerFunc, issuer string) {
	h.issuer = issuer

	// Authorization endpoints (no client auth middleware, client is identified by params)
	router.GET("/authorize", h.Authorize)
	router.POST("/authorize/login", h.AuthorizeLogin)
	router.POST("/authorize/mfa", h.AuthorizeMFA)
	router.POST("/authorize/consent", h.AuthorizeConsent)

	// Token endpoint (client auth required)
	router.POST("/token", clientAuth, h.Token)

	// Device code flow
	router.POST("/device_authorization", clientAuth, h.DeviceAuthorization)
	router.POST("/device/verify", h.DeviceVerify)
	router.POST("/device/approve", h.DeviceApprove)

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
		if h.auditService != nil {
			h.auditService.LogFromContext(c, audit.ActionUserLoginFailed, map[string]any{
				"email": input.Email,
				"flow":  "oauth",
			})
		}
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionUserLogin, map[string]any{
			"email": input.Email,
			"flow":  "oauth",
		})
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

// AuthorizeMFA handles the MFA verification step.
func (h *Handler) AuthorizeMFA(c *gin.Context) {
	var input AuthorizeMFAInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrInvalidRequest("invalid request body: "+err.Error()))
		return
	}

	resp, err := h.service.AuthorizeMFA(input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	// If no consent needed, auto-complete
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

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionOAuthConsentGranted, map[string]any{
			"request_id": input.RequestID,
		})
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
	case "urn:ietf:params:oauth:grant-type:device_code":
		h.handleDeviceCodeGrant(c, client)
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

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionTokenRevoked, map[string]any{
			"client_id": client.ID,
		})
	}

	pkg.OK(c, gin.H{})
}

// --- Device Code Flow ---

// DeviceAuthorization handles POST /device_authorization (RFC 8628).
func (h *Handler) DeviceAuthorization(c *gin.Context) {
	client, ok := middleware.GetOAuthClient(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrInvalidClient("client authentication required"))
		return
	}

	scope := c.PostForm("scope")
	resp, err := h.service.InitDeviceAuthorization(client, scope, h.issuer)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, resp)
}

// DeviceVerify handles POST /device/verify — user enters user_code.
func (h *Handler) DeviceVerify(c *gin.Context) {
	var input DeviceVerifyInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrInvalidRequest("invalid request body: "+err.Error()))
		return
	}

	resp, err := h.service.DeviceVerify(input.UserCode)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, resp)
}

// DeviceApprove handles POST /device/approve — authenticated user approves/denies.
func (h *Handler) DeviceApprove(c *gin.Context) {
	// This endpoint requires the user to be authenticated
	// The consuming app should pass user credentials or a session token
	var input struct {
		UserCode string `json:"user_code" binding:"required"`
		Approved bool   `json:"approved"`
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrInvalidRequest("invalid request body: "+err.Error()))
		return
	}

	// Authenticate the user
	u, err := h.service.userService.Authenticate(user.LoginInput{
		Email:    input.Email,
		Password: input.Password,
	})
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	err = h.service.DeviceApprove(DeviceApproveInput{
		UserCode: input.UserCode,
		Approved: input.Approved,
	}, u.ID, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	msg := "device authorization denied"
	if input.Approved {
		msg = "device authorization approved"
	}
	pkg.OK(c, gin.H{"message": msg})
}

func (h *Handler) handleDeviceCodeGrant(c *gin.Context, client *model.OAuthClient) {
	deviceCode := c.PostForm("device_code")
	if deviceCode == "" {
		pkg.HandleError(c, pkg.ErrInvalidRequest("missing device_code"))
		return
	}

	resp, err := h.service.ExchangeDeviceCode(client, deviceCode)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, resp)
}
