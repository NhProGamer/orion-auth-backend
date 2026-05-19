package client

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
)

// DCRHandler handles Dynamic Client Registration (RFC 7591 + RFC 7592).
type DCRHandler struct {
	service *Service
}

func NewDCRHandler(service *Service) *DCRHandler {
	return &DCRHandler{service: service}
}

// DCRRequest represents the OIDC Dynamic Client Registration request body.
type DCRRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
	BackchannelLogoutURI    string   `json:"backchannel_logout_uri"`
	FrontchannelLogoutURI   string   `json:"frontchannel_logout_uri"`
	JWKSUri                 string   `json:"jwks_uri"`
	SubjectType             string   `json:"subject_type"`
	RequirePKCE             *bool    `json:"require_pkce,omitempty"`
	RequestURIs             []string `json:"request_uris,omitempty"`
}

// DCRResponse represents the OIDC Dynamic Client Registration response.
type DCRResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	RequirePKCE             bool     `json:"require_pkce"`
	RequestURIs             []string `json:"request_uris,omitempty"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
}

// Register handles POST /register for Dynamic Client Registration.
func (h *DCRHandler) Register(c *gin.Context) {
	var req DCRRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.HandleError(c, pkg.ErrInvalidRequest("invalid request body"))
		return
	}

	if req.ClientName == "" {
		pkg.HandleError(c, pkg.ErrInvalidRequest("client_name is required"))
		return
	}
	if len(req.RedirectURIs) == 0 {
		pkg.HandleError(c, pkg.ErrInvalidRequest("redirect_uris is required"))
		return
	}

	// Set defaults
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}

	isPublic := req.TokenEndpointAuthMethod == "none"

	authMethod := req.TokenEndpointAuthMethod
	input := CreateInput{
		Name:            req.ClientName,
		RedirectURIs:    req.RedirectURIs,
		GrantTypes:      req.GrantTypes,
		ResponseTypes:   req.ResponseTypes,
		TokenAuthMethod: &authMethod,
		IsPublic:        isPublic,
		RequirePKCE:     req.RequirePKCE,
		RequestURIs:     req.RequestURIs,
	}

	if req.Scope != "" {
		input.Scopes = pq.StringArray(splitScopes(req.Scope))
	}

	result, err := h.service.Create(input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	// Generate registration_access_token
	rawRAT, ratHash, err := crypto.GenerateOpaqueToken()
	if err == nil && ratHash != "" {
		result.Client.RegistrationAccessTokenHash = &ratHash
		_ = h.service.repo.Update(result.Client)
	}

	resp := DCRResponse{
		ClientID:                result.Client.ID.String(),
		ClientSecret:            result.ClientSecret,
		ClientIDIssuedAt:        time.Now().Unix(),
		ClientSecretExpiresAt:   0,
		ClientName:              result.Client.Name,
		RedirectURIs:            result.Client.RedirectURIs,
		GrantTypes:              result.Client.GrantTypes,
		ResponseTypes:           result.Client.ResponseTypes,
		TokenEndpointAuthMethod: result.Client.TokenAuthMethod,
		RequirePKCE:             result.Client.RequirePKCE,
		RequestURIs:             result.Client.RequestURIs,
		RegistrationAccessToken: rawRAT,
	}

	c.JSON(http.StatusCreated, resp)
}

// ReadRegistration handles GET /register/:client_id (RFC 7592).
func (h *DCRHandler) ReadRegistration(c *gin.Context) {
	client, err := h.authenticateRAT(c)
	if err != nil {
		return
	}

	resp := DCRResponse{
		ClientID:                client.ID.String(),
		ClientIDIssuedAt:        client.CreatedAt.Unix(),
		ClientSecretExpiresAt:   0,
		ClientName:              client.Name,
		RedirectURIs:            client.RedirectURIs,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           client.ResponseTypes,
		TokenEndpointAuthMethod: client.TokenAuthMethod,
		RequirePKCE:             client.RequirePKCE,
		RequestURIs:             client.RequestURIs,
	}

	c.JSON(http.StatusOK, resp)
}

// UpdateRegistration handles PUT /register/:client_id (RFC 7592).
func (h *DCRHandler) UpdateRegistration(c *gin.Context) {
	client, err := h.authenticateRAT(c)
	if err != nil {
		return
	}

	var req DCRRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		pkg.HandleError(c, pkg.ErrInvalidRequest("invalid request body"))
		return
	}

	if req.ClientName != "" {
		client.Name = req.ClientName
	}
	if len(req.RedirectURIs) > 0 {
		client.RedirectURIs = pq.StringArray(req.RedirectURIs)
	}
	if len(req.GrantTypes) > 0 {
		client.GrantTypes = pq.StringArray(req.GrantTypes)
	}
	if len(req.ResponseTypes) > 0 {
		client.ResponseTypes = pq.StringArray(req.ResponseTypes)
	}
	if req.TokenEndpointAuthMethod != "" {
		client.TokenAuthMethod = req.TokenEndpointAuthMethod
	}
	if req.Scope != "" {
		client.Scopes = pq.StringArray(splitScopes(req.Scope))
	}
	if req.RequirePKCE != nil {
		client.RequirePKCE = *req.RequirePKCE
	}
	if req.RequestURIs != nil {
		client.RequestURIs = pq.StringArray(req.RequestURIs)
	}

	if err := h.service.repo.Update(client); err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to update client"))
		return
	}

	resp := DCRResponse{
		ClientID:                client.ID.String(),
		ClientIDIssuedAt:        client.CreatedAt.Unix(),
		ClientSecretExpiresAt:   0,
		ClientName:              client.Name,
		RedirectURIs:            client.RedirectURIs,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           client.ResponseTypes,
		TokenEndpointAuthMethod: client.TokenAuthMethod,
		RequirePKCE:             client.RequirePKCE,
		RequestURIs:             client.RequestURIs,
	}

	c.JSON(http.StatusOK, resp)
}

// DeleteRegistration handles DELETE /register/:client_id (RFC 7592).
func (h *DCRHandler) DeleteRegistration(c *gin.Context) {
	client, err := h.authenticateRAT(c)
	if err != nil {
		return
	}

	if err := h.service.repo.Delete(client.ID); err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to delete client"))
		return
	}

	c.Status(http.StatusNoContent)
}

// authenticateRAT validates the registration_access_token from the Bearer header.
func (h *DCRHandler) authenticateRAT(c *gin.Context) (*model.OAuthClient, error) {
	clientIDStr := c.Param("client_id")
	clientID, err := uuid.Parse(clientIDStr)
	if err != nil {
		pkg.HandleError(c, pkg.ErrInvalidRequest("invalid client_id"))
		return nil, err
	}

	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		pkg.HandleError(c, pkg.ErrUnauthorized("missing registration_access_token"))
		return nil, pkg.ErrUnauthorized("missing token")
	}
	rawToken := strings.TrimPrefix(authHeader, "Bearer ")
	tokenHash := crypto.HashToken(rawToken)

	client, err := h.service.repo.FindByID(clientID)
	if err != nil || client == nil {
		pkg.HandleError(c, pkg.ErrNotFound("client not found"))
		return nil, pkg.ErrNotFound("client not found")
	}

	if client.RegistrationAccessTokenHash == nil || *client.RegistrationAccessTokenHash != tokenHash {
		pkg.HandleError(c, pkg.ErrUnauthorized("invalid registration_access_token"))
		return nil, pkg.ErrUnauthorized("invalid token")
	}

	return client, nil
}

func splitScopes(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			if i > start {
				result = append(result, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
}
