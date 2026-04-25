package client

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lib/pq"

	"orion-auth-backend/crypto"
	"orion-auth-backend/pkg"
)

// DCRHandler handles Dynamic Client Registration (RFC 7591).
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
}

// DCRResponse represents the OIDC Dynamic Client Registration response.
type DCRResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
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
		ClientName:              result.Client.Name,
		RedirectURIs:            result.Client.RedirectURIs,
		GrantTypes:              result.Client.GrantTypes,
		ResponseTypes:           result.Client.ResponseTypes,
		TokenEndpointAuthMethod: result.Client.TokenAuthMethod,
		RegistrationAccessToken: rawRAT,
	}

	c.JSON(http.StatusCreated, resp)
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
