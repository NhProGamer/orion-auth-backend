package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"orion-auth-backend/config"
	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
	"orion-auth-backend/policy/inputs"
	"orion-auth-backend/session"
	"orion-auth-backend/user"
)

// IDTokenGenerator is an interface to avoid circular imports with the oidc package.
type IDTokenGenerator interface {
	GenerateIDToken(claims IDTokenClaims) (string, error)
}

// MFAValidator is an interface to avoid circular imports with the mfa package.
type MFAValidator interface {
	HasMFA(userID uuid.UUID) (bool, error)
	ValidateCode(userID uuid.UUID, code string) (bool, error)
}

// PolicyEvaluator is an interface to avoid circular imports with the policy package.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, policyType string, input map[string]any) (*PolicyResult, error)
}

// PolicyResult mirrors policy.EvalResult to avoid circular imports.
type PolicyResult struct {
	Allow      bool
	Deny       bool
	DenyReason string
	Modify     map[string]any
}

// ResourceValidator validates audience and scopes against API resources.
type ResourceValidator interface {
	ValidateAudience(audience string) (*model.APIResource, error)
	ValidateClientScopes(clientID, resourceID uuid.UUID, requestedScopes []string) ([]string, error)
	ValidateUserScopes(userID, resourceID uuid.UUID, requestedScopes []string) ([]string, error)
}

// IDTokenValidator validates and extracts claims from an existing ID token.
type IDTokenValidator interface {
	ValidateIDToken(tokenString string) (uuid.UUID, error)
}

// RoleProvider supplies role and permission names for a user. Used to enrich
// policy inputs without coupling oauth to the rbac package.
type RoleProvider interface {
	GetUserRoleNames(userID uuid.UUID) ([]string, error)
	GetUserPermissions(userID uuid.UUID) ([]string, error)
}

// IDTokenClaims mirrors oidc.IDTokenClaims to avoid circular imports.
type IDTokenClaims struct {
	UserID           uuid.UUID
	ClientID         uuid.UUID
	Scopes           []string
	Nonce            string
	AuthTime         time.Time
	ATHash           string
	CHash            string
	SHash            string
	TTL              time.Duration
	RequestedClaims  string
	ACR              string
	AMR              []string
	SubjectType      string
	SectorIdentifier string
	ExtraClaims      map[string]any // custom claims injected via policy modify
}

type Service struct {
	repo              RepositoryInterface
	userService       *user.Service
	sessionService    *session.Service
	hasher            *crypto.Argon2Hasher
	cfg               config.AuthConfig
	issuer            string
	idTokenGen        IDTokenGenerator
	mfaValidator      MFAValidator
	policyEvaluator   PolicyEvaluator
	resourceValidator ResourceValidator
	idTokenValidator  IDTokenValidator
	roleProvider      RoleProvider
}

func NewService(
	repo RepositoryInterface,
	userService *user.Service,
	sessionService *session.Service,
	hasher *crypto.Argon2Hasher,
	cfg config.AuthConfig,
) *Service {
	return &Service{
		repo:           repo,
		userService:    userService,
		sessionService: sessionService,
		hasher:         hasher,
		cfg:            cfg,
	}
}

// SetIDTokenGenerator sets the OIDC ID token generator (called after init to break circular dep).
func (s *Service) SetIDTokenGenerator(gen IDTokenGenerator) {
	s.idTokenGen = gen
}

// SetMFAValidator sets the MFA validator (called after init to break circular dep).
func (s *Service) SetMFAValidator(v MFAValidator) {
	s.mfaValidator = v
}

// SetPolicyEvaluator sets the policy evaluator (called after init to break circular dep).
func (s *Service) SetPolicyEvaluator(p PolicyEvaluator) {
	s.policyEvaluator = p
}

// SetResourceValidator sets the resource validator (called after init to break circular dep).
func (s *Service) SetResourceValidator(v ResourceValidator) {
	s.resourceValidator = v
}

// SetIDTokenValidator sets the ID token validator (called after init to break circular dep).
func (s *Service) SetIDTokenValidator(v IDTokenValidator) {
	s.idTokenValidator = v
}

// SetRoleProvider wires the source of roles + permissions used to enrich
// policy inputs. Optional — when absent, input.user.roles and .permissions
// remain empty arrays.
func (s *Service) SetRoleProvider(p RoleProvider) {
	s.roleProvider = p
}

// loadRoles fetches role + permission names for the given user, returning empty
// slices when the role provider isn't configured or the lookup fails. Errors
// are intentionally swallowed: a policy decision should not block on RBAC IO.
func (s *Service) loadRoles(userID uuid.UUID) (roles, permissions []string) {
	if s.roleProvider == nil {
		return nil, nil
	}
	if r, err := s.roleProvider.GetUserRoleNames(userID); err == nil {
		roles = r
	}
	if p, err := s.roleProvider.GetUserPermissions(userID); err == nil {
		permissions = p
	}
	return roles, permissions
}

// SetIssuer sets the issuer URL for authorization response iss parameter (RFC 9207).
func (s *Service) SetIssuer(issuer string) {
	s.issuer = issuer
}

// TokenResponse is the standard OAuth2 token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// --- Authorization Request (API-driven) ---

type ResourceInfo struct {
	Name        string                   `json:"name"`
	Identifier  string                   `json:"identifier"`
	Permissions []ResourcePermissionInfo `json:"permissions"`
}

type ResourcePermissionInfo struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

// InitAuthorizeParams holds all parameters for the authorization request.
type InitAuthorizeParams struct {
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Audience            string
	// OIDC Core parameters
	Prompt        string
	MaxAge        string
	Display       string
	UILocales     string
	ClaimsLocales string
	ACRValues     string
	LoginHint     string
	Claims        string
	IDTokenHint   string
	ResponseMode  string
}

type InitAuthorizeResponse struct {
	RequestID       uuid.UUID                 `json:"request_id"`
	ClientName      string                    `json:"client_name"`
	ClientID        uuid.UUID                 `json:"client_id"`
	ScopesRequested []string                  `json:"scopes_requested"`
	RequiresLogin   bool                      `json:"requires_login"`
	RequiresConsent bool                      `json:"requires_consent"`
	Resource        *ResourceInfo             `json:"resource,omitempty"`
	LoginHint       string                    `json:"login_hint,omitempty"`
	Display         string                    `json:"display,omitempty"`
	Prompt          string                    `json:"prompt,omitempty"`
	ResponseMode    string                    `json:"response_mode,omitempty"`
	Redirect        *AuthorizeConsentResponse `json:"redirect,omitempty"`
}

// --- Pushed Authorization Requests (RFC 9126) ---

type PARResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

func (s *Service) CreatePAR(client *model.OAuthClient, params InitAuthorizeParams) (*PARResponse, error) {
	// Validate the params (same as InitAuthorize but don't execute)
	if !isValidResponseType(params.ResponseType) {
		return nil, pkg.ErrUnsupportedResponseType("invalid response_type")
	}
	if !client.HasRedirectURI(params.RedirectURI) {
		return nil, pkg.ErrInvalidRequest("invalid redirect_uri")
	}

	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, pkg.ErrServerError("failed to serialize PAR params")
	}

	requestURI := "urn:ietf:params:oauth:request_uri:" + uuid.Must(uuid.NewV7()).String()
	expiresIn := 60

	par := &model.PushedAuthorizationRequest{
		RequestURI: requestURI,
		ClientID:   client.ID,
		Params:     string(paramsJSON),
		ExpiresAt:  time.Now().Add(time.Duration(expiresIn) * time.Second),
	}

	if err := s.repo.CreatePAR(par); err != nil {
		return nil, pkg.ErrServerError("failed to store PAR")
	}

	return &PARResponse{
		RequestURI: requestURI,
		ExpiresIn:  expiresIn,
	}, nil
}

func (s *Service) InitAuthorizeFromPAR(requestURI, clientIDStr string) (*InitAuthorizeResponse, error) {
	par, err := s.repo.FindPAR(requestURI)
	if err != nil || par == nil {
		return nil, pkg.ErrInvalidRequest("invalid or expired request_uri")
	}

	// Verify client_id matches
	if par.ClientID.String() != clientIDStr {
		return nil, pkg.ErrInvalidRequest("client_id mismatch")
	}

	// Delete PAR (one-time use)
	_ = s.repo.DeletePAR(requestURI)

	// Deserialize params
	var params InitAuthorizeParams
	if err := json.Unmarshal([]byte(par.Params), &params); err != nil {
		return nil, pkg.ErrServerError("failed to parse PAR params")
	}

	// Look up client and proceed with normal authorize flow
	client, err := s.repo.findClient(clientIDStr)
	if err != nil {
		return nil, err
	}

	return s.InitAuthorize(client, params)
}

func (s *Service) InitAuthorize(client *model.OAuthClient, params InitAuthorizeParams) (*InitAuthorizeResponse, error) {
	// Validate response_type
	if !isValidResponseType(params.ResponseType) {
		return nil, pkg.ErrUnsupportedResponseType("supported response_types: code, code id_token, code token, code id_token token")
	}

	// Validate redirect_uri
	if !client.HasRedirectURI(params.RedirectURI) {
		return nil, pkg.ErrInvalidRequest("invalid redirect_uri")
	}

	// Validate grant type
	if !client.HasGrantType("authorization_code") {
		return nil, pkg.ErrUnauthorizedClient("client is not authorized for authorization_code grant")
	}

	// PKCE: always required for public clients; required for confidential clients
	// unless explicitly opted out via client.RequirePKCE = false.
	if (client.IsPublic || client.RequirePKCE) && params.CodeChallenge == "" {
		return nil, pkg.ErrInvalidRequest("PKCE (code_challenge) is required")
	}

	// Only S256 allowed
	if params.CodeChallenge != "" && params.CodeChallengeMethod != "S256" && params.CodeChallengeMethod != "" {
		return nil, pkg.ErrInvalidRequest("only S256 code_challenge_method is supported")
	}
	if params.CodeChallenge != "" && params.CodeChallengeMethod == "" {
		params.CodeChallengeMethod = "S256"
	}

	// Validate prompt parameter
	if params.Prompt != "" {
		switch params.Prompt {
		case "none", "login", "consent", "select_account":
			// valid
		default:
			return nil, pkg.ErrInvalidRequest("invalid prompt value")
		}
	}

	// Validate display parameter
	if params.Display != "" {
		switch params.Display {
		case "page", "popup", "touch", "wap":
			// valid
		default:
			return nil, pkg.ErrInvalidRequest("invalid display value")
		}
	}

	// Validate response_mode parameter
	if params.ResponseMode != "" {
		switch params.ResponseMode {
		case "query", "fragment", "form_post":
			// valid
		default:
			return nil, pkg.ErrInvalidRequest("invalid response_mode value")
		}
	}

	// Validate max_age parameter
	var maxAge *int
	if params.MaxAge != "" {
		v, err := strconv.Atoi(params.MaxAge)
		if err != nil || v < 0 {
			return nil, pkg.ErrInvalidRequest("max_age must be a non-negative integer")
		}
		maxAge = &v
	}

	// Validate claims parameter (must be valid JSON if present)
	if params.Claims != "" {
		var tmp json.RawMessage
		if err := json.Unmarshal([]byte(params.Claims), &tmp); err != nil {
			return nil, pkg.ErrInvalidRequest("invalid claims parameter: must be valid JSON")
		}
	}

	// Handle prompt=select_account (not supported)
	if params.Prompt == "select_account" {
		return nil, pkg.ErrAccountSelectionRequired("account selection is not supported")
	}

	// Validate audience and scopes
	var validatedAudience *string
	var resourceInfo *ResourceInfo
	var scopes []string

	if params.Audience != "" && s.resourceValidator != nil {
		resource, err := s.resourceValidator.ValidateAudience(params.Audience)
		if err != nil {
			return nil, err
		}
		resourceScopes, err := s.resourceValidator.ValidateClientScopes(client.ID, resource.ID, parseSpaceDelimited(params.Scope))
		if err != nil {
			return nil, err
		}
		if len(resourceScopes) == 0 {
			return nil, pkg.ErrInvalidScope("client has no permissions for this resource")
		}
		scopes = resourceScopes
		validatedAudience = &params.Audience

		// Build resource info for consent screen
		var perms []ResourcePermissionInfo
		for _, p := range resource.Permissions {
			perms = append(perms, ResourcePermissionInfo{Name: p.Name, Description: p.Description})
		}
		resourceInfo = &ResourceInfo{
			Name:        resource.Name,
			Identifier:  resource.Identifier,
			Permissions: perms,
		}
	} else {
		// Standard scope validation against client
		scopes = client.ValidateScopes(parseSpaceDelimited(params.Scope))
		if len(scopes) == 0 {
			return nil, pkg.ErrInvalidScope("no valid scopes requested")
		}
	}

	// Handle prompt=none (silent authentication)
	if params.Prompt == "none" {
		return s.handlePromptNone(client, params, scopes, validatedAudience, resourceInfo)
	}

	// Create authorization request
	req := &model.AuthorizationRequest{
		ClientID:     client.ID,
		RedirectURI:  params.RedirectURI,
		ResponseType: params.ResponseType,
		Scopes:       pq.StringArray(scopes),
		Audience:     validatedAudience,
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	}

	if params.State != "" {
		req.State = &params.State
	}
	if params.Nonce != "" {
		req.Nonce = &params.Nonce
	}
	if params.CodeChallenge != "" {
		req.CodeChallenge = &params.CodeChallenge
		req.CodeChallengeMethod = &params.CodeChallengeMethod
	}
	if params.Prompt != "" {
		req.Prompt = &params.Prompt
	}
	if maxAge != nil {
		req.MaxAge = maxAge
	}
	if params.Display != "" {
		req.Display = &params.Display
	}
	if params.UILocales != "" {
		req.UILocales = &params.UILocales
	}
	if params.ClaimsLocales != "" {
		req.ClaimsLocales = &params.ClaimsLocales
	}
	if params.ACRValues != "" {
		req.ACRValues = &params.ACRValues
	}
	if params.LoginHint != "" {
		req.LoginHint = &params.LoginHint
	}
	if params.Claims != "" {
		req.ClaimsParam = &params.Claims
	}
	if params.IDTokenHint != "" {
		req.IDTokenHint = &params.IDTokenHint
	}
	if params.ResponseMode != "" {
		req.ResponseMode = &params.ResponseMode
	}

	if err := s.repo.CreateAuthRequest(req); err != nil {
		slog.Error("failed to create auth request", "error", err)
		return nil, pkg.ErrServerError("failed to create authorization request")
	}

	// Determine login/consent requirements
	requiresLogin := true
	requiresConsent := !client.IsFirstParty
	if params.Prompt == "consent" {
		requiresConsent = true
	}

	return &InitAuthorizeResponse{
		RequestID:       req.ID,
		ClientName:      client.Name,
		ClientID:        client.ID,
		ScopesRequested: scopes,
		RequiresLogin:   requiresLogin,
		RequiresConsent: requiresConsent,
		Resource:        resourceInfo,
		LoginHint:       params.LoginHint,
		Display:         params.Display,
		Prompt:          params.Prompt,
		ResponseMode:    params.ResponseMode,
	}, nil
}

// handlePromptNone handles silent authentication (prompt=none).
// It requires a valid id_token_hint to identify the user and existing consent.
func (s *Service) handlePromptNone(client *model.OAuthClient, params InitAuthorizeParams, scopes []string, audience *string, resource *ResourceInfo) (*InitAuthorizeResponse, error) {
	if params.IDTokenHint == "" || s.idTokenValidator == nil {
		return nil, pkg.ErrLoginRequired("prompt=none requires id_token_hint")
	}

	userID, err := s.idTokenValidator.ValidateIDToken(params.IDTokenHint)
	if err != nil {
		return nil, pkg.ErrLoginRequired("invalid id_token_hint")
	}

	// Check existing consent
	consent, _ := s.repo.FindActiveConsent(userID, client.ID)
	if consent == nil || !consent.CoversScopes(scopes) {
		if !client.IsFirstParty {
			return nil, pkg.ErrConsentRequired("user has not consented to the requested scopes")
		}
	}

	// Create a temporary auth request for completeAuthorize
	req := &model.AuthorizationRequest{
		ClientID:      client.ID,
		RedirectURI:   params.RedirectURI,
		ResponseType:  params.ResponseType,
		Scopes:        pq.StringArray(scopes),
		Audience:      audience,
		UserID:        &userID,
		Authenticated: true,
		ConsentGiven:  true,
		ExpiresAt:     time.Now().Add(1 * time.Minute),
	}
	if params.State != "" {
		req.State = &params.State
	}
	if params.Nonce != "" {
		req.Nonce = &params.Nonce
	}
	if params.CodeChallenge != "" {
		req.CodeChallenge = &params.CodeChallenge
		req.CodeChallengeMethod = &params.CodeChallengeMethod
	}
	if params.Claims != "" {
		req.ClaimsParam = &params.Claims
	}
	now := time.Now()
	req.AuthTime = &now

	if err := s.repo.CreateAuthRequest(req); err != nil {
		return nil, pkg.ErrServerError("failed to create authorization request")
	}

	// Complete the flow immediately (no UI interaction)
	redirect, err := s.completeAuthorize(req, "", "")
	if err != nil {
		return nil, err
	}

	return &InitAuthorizeResponse{
		RequestID:       req.ID,
		ClientName:      client.Name,
		ClientID:        client.ID,
		ScopesRequested: scopes,
		Redirect:        redirect,
	}, nil
}

type AuthorizeLoginInput struct {
	RequestID uuid.UUID `json:"request_id" binding:"required"`
	Email     string    `json:"email" binding:"required,email"`
	Password  string    `json:"password" binding:"required"`
}

type AuthorizeLoginResponse struct {
	RequestID       uuid.UUID `json:"request_id"`
	Authenticated   bool      `json:"authenticated"`
	RequiresConsent bool      `json:"requires_consent"`
	RequiresMFA     bool      `json:"requires_mfa"`
	Scopes          []string  `json:"scopes"`
}

func (s *Service) AuthorizeLogin(input AuthorizeLoginInput, ipAddress, userAgent string) (*AuthorizeLoginResponse, error) {
	req, err := s.repo.FindAuthRequest(input.RequestID)
	if err != nil || req == nil {
		return nil, pkg.ErrInvalidRequest("invalid or expired authorization request")
	}
	if req.IsExpired() {
		return nil, pkg.ErrInvalidRequest("authorization request expired")
	}
	if req.Authenticated {
		return nil, pkg.ErrInvalidRequest("already authenticated")
	}

	// Authenticate user
	u, err := s.userService.Authenticate(user.LoginInput{
		Email:    input.Email,
		Password: input.Password,
	})
	if err != nil {
		return nil, err
	}

	// Evaluate login policies
	if s.policyEvaluator != nil {
		roles, perms := s.loadRoles(u.ID)
		pInput := inputs.BuildLoginInput(u, nil, roles, perms, ipAddress, userAgent)
		result, pErr := s.policyEvaluator.Evaluate(context.Background(), "login", pInput)
		if pErr != nil {
			slog.Warn("login policy evaluation failed", "error", pErr)
		} else if result != nil && result.Deny {
			return nil, pkg.ErrAccessDenied(result.DenyReason)
		}
	}

	// Check if consent already given
	var needsConsent bool
	consent, _ := s.repo.FindActiveConsent(u.ID, req.ClientID)
	if consent != nil && consent.CoversScopes(req.Scopes) {
		needsConsent = false
	} else {
		// First-party clients skip consent
		client, err := s.repo.findClient(req.ClientID.String())
		if err != nil {
			return nil, pkg.ErrServerError("failed to look up client")
		}
		needsConsent = !client.IsFirstParty
	}

	// Check if user has MFA enabled
	hasMFA := false
	if s.mfaValidator != nil {
		hasMFA, _ = s.mfaValidator.HasMFA(u.ID)
	}
	needsMFA := hasMFA

	// Evaluate MFA policies — may force MFA on or off based on context.
	if s.policyEvaluator != nil {
		client, _ := s.repo.findClient(req.ClientID.String())
		roles, perms := s.loadRoles(u.ID)
		pInput := inputs.BuildMFAInput(u, client, roles, perms, []string(req.Scopes), hasMFA, ipAddress, userAgent)
		result, pErr := s.policyEvaluator.Evaluate(context.Background(), "mfa", pInput)
		if pErr != nil {
			slog.Warn("mfa policy evaluation failed", "error", pErr)
		} else if result != nil {
			if result.Deny {
				return nil, pkg.ErrAccessDenied(result.DenyReason)
			}
			if v, ok := readModifyBool(result.Modify, "require_mfa"); ok {
				if v && !hasMFA {
					return nil, pkg.ErrAccessDenied("multi-factor authentication required but not enrolled")
				}
				needsMFA = v
			}
		}
	}

	req.UserID = &u.ID
	req.AuthMethods = append(req.AuthMethods, "pwd")
	now := time.Now()
	if needsMFA {
		// Don't mark as authenticated yet — MFA step required
	} else {
		req.Authenticated = true
		req.AuthTime = &now
	}

	// prompt=consent forces consent even for first-party or pre-consented clients
	if req.Prompt != nil && *req.Prompt == "consent" {
		needsConsent = true
	}

	if !needsConsent && req.Authenticated {
		req.ConsentGiven = true
	}

	if err := s.repo.UpdateAuthRequest(req); err != nil {
		return nil, pkg.ErrServerError("failed to update authorization request")
	}

	return &AuthorizeLoginResponse{
		RequestID:       req.ID,
		Authenticated:   !needsMFA,
		RequiresConsent: needsConsent,
		RequiresMFA:     needsMFA,
		Scopes:          req.Scopes,
	}, nil
}

// --- MFA Step ---

type AuthorizeMFAInput struct {
	RequestID uuid.UUID `json:"request_id" binding:"required"`
	Code      string    `json:"code" binding:"required"`
}

func (s *Service) AuthorizeMFA(input AuthorizeMFAInput) (*AuthorizeLoginResponse, error) {
	req, err := s.repo.FindAuthRequest(input.RequestID)
	if err != nil || req == nil {
		return nil, pkg.ErrInvalidRequest("invalid or expired authorization request")
	}
	if req.IsExpired() {
		return nil, pkg.ErrInvalidRequest("authorization request expired")
	}
	if req.UserID == nil {
		return nil, pkg.ErrInvalidRequest("must authenticate first")
	}
	if req.Authenticated {
		return nil, pkg.ErrInvalidRequest("MFA already completed")
	}

	if s.mfaValidator == nil {
		return nil, pkg.ErrServerError("MFA validator not configured")
	}

	valid, err := s.mfaValidator.ValidateCode(*req.UserID, input.Code)
	if err != nil || !valid {
		return nil, pkg.ErrAccessDenied("invalid MFA code")
	}

	req.Authenticated = true
	req.AuthMethods = append(req.AuthMethods, "otp")
	now := time.Now()
	req.AuthTime = &now

	// Check consent
	var needsConsent bool
	consent, _ := s.repo.FindActiveConsent(*req.UserID, req.ClientID)
	if consent != nil && consent.CoversScopes(req.Scopes) {
		needsConsent = false
		req.ConsentGiven = true
	} else {
		client, err := s.repo.findClient(req.ClientID.String())
		if err != nil {
			return nil, pkg.ErrServerError("failed to look up client")
		}
		needsConsent = !client.IsFirstParty
		if !needsConsent {
			req.ConsentGiven = true
		}
	}

	// prompt=consent forces consent
	if req.Prompt != nil && *req.Prompt == "consent" {
		needsConsent = true
		req.ConsentGiven = false
	}

	if err := s.repo.UpdateAuthRequest(req); err != nil {
		return nil, pkg.ErrServerError("failed to update authorization request")
	}

	return &AuthorizeLoginResponse{
		RequestID:       req.ID,
		Authenticated:   true,
		RequiresConsent: needsConsent,
		RequiresMFA:     false,
		Scopes:          req.Scopes,
	}, nil
}

type AuthorizeConsentInput struct {
	RequestID     uuid.UUID `json:"request_id" binding:"required"`
	ScopesGranted []string  `json:"scopes_granted" binding:"required"`
}

type AuthorizeConsentResponse struct {
	RedirectURI  string `json:"redirect_uri"`
	Code         string `json:"code,omitempty"`
	State        string `json:"state,omitempty"`
	Issuer       string `json:"iss,omitempty"`
	SessionState string `json:"session_state,omitempty"`
	ResponseMode string `json:"response_mode,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

func (s *Service) AuthorizeConsent(input AuthorizeConsentInput, ipAddress, userAgent string) (*AuthorizeConsentResponse, error) {
	req, err := s.repo.FindAuthRequest(input.RequestID)
	if err != nil || req == nil {
		return nil, pkg.ErrInvalidRequest("invalid or expired authorization request")
	}
	if req.IsExpired() {
		return nil, pkg.ErrInvalidRequest("authorization request expired")
	}
	if !req.Authenticated {
		return nil, pkg.ErrInvalidRequest("must authenticate first")
	}
	if req.UserID == nil {
		return nil, pkg.ErrServerError("authorization request has no user")
	}

	// Validate scopes granted are subset of requested
	grantedScopes := filterScopes(input.ScopesGranted, req.Scopes)
	if len(grantedScopes) == 0 {
		return nil, pkg.ErrInvalidScope("no valid scopes granted")
	}

	// Evaluate consent policies — they may deny outright or narrow grantedScopes.
	if s.policyEvaluator != nil {
		var u *model.User
		if s.userService != nil {
			u, _ = s.userService.GetByID(*req.UserID)
		}
		client, _ := s.repo.findClient(req.ClientID.String())
		if u != nil && client != nil {
			roles, perms := s.loadRoles(u.ID)
			pInput := inputs.BuildConsentInput(u, client, roles, perms, []string(req.Scopes), grantedScopes, ipAddress, userAgent)
			result, pErr := s.policyEvaluator.Evaluate(context.Background(), "consent", pInput)
			if pErr != nil {
				slog.Warn("consent policy evaluation failed", "error", pErr)
			} else if result != nil {
				if result.Deny {
					return nil, pkg.ErrAccessDenied(result.DenyReason)
				}
				if result.Modify != nil {
					if narrowed, ok := readModifyScopes(result.Modify, pq.StringArray(grantedScopes)); ok {
						grantedScopes = []string(narrowed)
						if len(grantedScopes) == 0 {
							return nil, pkg.ErrAccessDenied("policy narrowed all scopes")
						}
					}
				}
			}
		}
	}

	// Store/update consent
	consent, _ := s.repo.FindActiveConsent(*req.UserID, req.ClientID)
	if consent == nil {
		consent = &model.Consent{
			UserID:    *req.UserID,
			ClientID:  req.ClientID,
			Scopes:    pq.StringArray(grantedScopes),
			GrantedAt: time.Now(),
		}
		if err := s.repo.CreateConsent(consent); err != nil {
			return nil, pkg.ErrServerError("failed to store consent")
		}
	} else {
		consent.Scopes = pq.StringArray(grantedScopes)
		consent.GrantedAt = time.Now()
		if err := s.repo.UpdateConsent(consent); err != nil {
			return nil, pkg.ErrServerError("failed to update consent")
		}
	}

	req.ConsentGiven = true
	req.Scopes = pq.StringArray(grantedScopes)
	if err := s.repo.UpdateAuthRequest(req); err != nil {
		return nil, pkg.ErrServerError("failed to update authorization request")
	}

	return s.completeAuthorize(req, ipAddress, userAgent)
}

// CompleteAuthorizeFirstParty generates the code when no consent is needed (first-party or pre-consented).
func (s *Service) CompleteAuthorizeFirstParty(requestID uuid.UUID, ipAddress, userAgent string) (*AuthorizeConsentResponse, error) {
	req, err := s.repo.FindAuthRequest(requestID)
	if err != nil || req == nil {
		return nil, pkg.ErrInvalidRequest("invalid or expired authorization request")
	}
	if !req.IsReady() {
		return nil, pkg.ErrInvalidRequest("authorization request is not ready")
	}
	return s.completeAuthorize(req, ipAddress, userAgent)
}

func (s *Service) completeAuthorize(req *model.AuthorizationRequest, ipAddress, userAgent string) (*AuthorizeConsentResponse, error) {
	// Create session
	sess, err := s.sessionService.Create(session.CreateInput{
		UserID:    *req.UserID,
		IPAddress: ipAddress,
		UserAgent: userAgent,
	})
	if err != nil {
		return nil, pkg.ErrServerError("failed to create session")
	}

	// Clean up auth request
	if err := s.repo.DeleteAuthRequest(req.ID); err != nil {
		slog.Error("failed to delete auth request", "id", req.ID, "error", err)
	}

	// Authorization code flow
	rawCode, codeHash, err := crypto.GenerateOpaqueToken()
	if err != nil {
		return nil, pkg.ErrServerError("failed to generate authorization code")
	}

	authCode := &model.AuthorizationCode{
		CodeHash:    codeHash,
		ClientID:    req.ClientID,
		UserID:      *req.UserID,
		RedirectURI: req.RedirectURI,
		Scopes:      req.Scopes,
		Audience:    req.Audience,
		SessionID:   &sess.ID,
		ExpiresAt:   time.Now().Add(s.cfg.AuthCodeTTL),
	}
	if req.CodeChallenge != nil {
		authCode.CodeChallenge = req.CodeChallenge
		authCode.CodeChallengeMethod = req.CodeChallengeMethod
	}
	if req.Nonce != nil {
		authCode.Nonce = req.Nonce
	}
	if req.AuthTime != nil {
		authCode.AuthTime = req.AuthTime
	}
	if req.ClaimsParam != nil {
		authCode.ClaimsParam = req.ClaimsParam
	}
	if len(req.AuthMethods) > 0 {
		authCode.AuthMethods = req.AuthMethods
	}

	if err := s.repo.CreateAuthCode(authCode); err != nil {
		return nil, pkg.ErrServerError("failed to create authorization code")
	}

	resp := &AuthorizeConsentResponse{
		RedirectURI: req.RedirectURI,
		Code:        rawCode,
		Issuer:      s.issuer,
	}
	if req.State != nil {
		resp.State = *req.State
	}
	if req.ResponseMode != nil {
		resp.ResponseMode = *req.ResponseMode
	}

	// Compute session_state (OIDC Session Management 1.0)
	resp.SessionState = computeSessionState(req.ClientID.String(), req.RedirectURI, sess.ID.String())

	// Hybrid flows: issue additional tokens in the authorization response
	if isHybridResponseType(req.ResponseType) {
		// Default to fragment for hybrid flows (OIDC Core Section 3.3)
		if resp.ResponseMode == "" {
			resp.ResponseMode = "fragment"
		}

		// Issue access token if response_type includes "token"
		if responseTypeIncludes(req.ResponseType, "token") {
			client, err := s.repo.findClient(req.ClientID.String())
			if err != nil {
				return nil, pkg.ErrServerError("failed to look up client")
			}
			rawAT, atHash, err := crypto.GenerateOpaqueToken()
			if err != nil {
				return nil, pkg.ErrServerError("failed to generate access token")
			}
			accessToken := &model.AccessToken{
				ID:        atHash,
				ClientID:  client.ID,
				UserID:    req.UserID,
				SessionID: &sess.ID,
				Scopes:    req.Scopes,
				Audience:  req.Audience,
				ExpiresAt: time.Now().Add(time.Duration(client.AccessTokenTTL) * time.Second),
			}
			if err := s.repo.CreateAccessToken(accessToken); err != nil {
				return nil, pkg.ErrServerError("failed to store access token")
			}
			resp.AccessToken = rawAT
			resp.TokenType = "Bearer"
			resp.ExpiresIn = client.AccessTokenTTL
		}

		// Issue ID token if response_type includes "id_token"
		if responseTypeIncludes(req.ResponseType, "id_token") && s.idTokenGen != nil {
			client, err := s.repo.findClient(req.ClientID.String())
			if err != nil {
				return nil, pkg.ErrServerError("failed to look up client")
			}
			var nonce string
			if req.Nonce != nil {
				nonce = *req.Nonce
			}
			authTime := time.Now()
			if req.AuthTime != nil {
				authTime = *req.AuthTime
			}
			acr, amr := computeACR(req.AuthMethods)
			sectorID := ""
			if client.SectorIdentifierURI != nil {
				sectorID = *client.SectorIdentifierURI
			}
			idTokenClaims := IDTokenClaims{
				UserID:           *req.UserID,
				ClientID:         req.ClientID,
				Scopes:           req.Scopes,
				Nonce:            nonce,
				AuthTime:         authTime,
				TTL:              time.Duration(client.IDTokenTTL) * time.Second,
				ACR:              acr,
				AMR:              amr,
				SubjectType:      client.SubjectType,
				SectorIdentifier: sectorID,
			}
			idToken, err := s.generateHybridIDToken(idTokenClaims, rawCode, resp.AccessToken, resp.State)
			if err != nil {
				slog.Warn("failed to generate hybrid ID token", "error", err)
			} else {
				resp.IDToken = idToken
			}
		}
	}

	slog.Info("authorization code issued", "client_id", req.ClientID, "user_id", req.UserID)
	return resp, nil
}

// generateHybridIDToken creates an ID token for hybrid flows with c_hash and optional at_hash/s_hash.
func (s *Service) generateHybridIDToken(claims IDTokenClaims, code, accessToken, state string) (string, error) {
	claims.CHash = computeATHash(code)
	if accessToken != "" {
		claims.ATHash = computeATHash(accessToken)
	}
	if state != "" {
		claims.SHash = computeATHash(state)
	}
	return s.idTokenGen.GenerateIDToken(claims)
}

// --- Token Exchange: Authorization Code ---

func (s *Service) ExchangeAuthorizationCode(client *model.OAuthClient, code, redirectURI, codeVerifier string) (*TokenResponse, error) {
	codeHash := crypto.HashToken(code)

	var resp *TokenResponse
	err := s.repo.Transaction(func(tx RepositoryInterface) error {
		authCode, err := tx.FindAuthCode(codeHash)
		if err != nil || authCode == nil {
			return pkg.ErrInvalidGrant("invalid authorization code")
		}

		if !authCode.IsValid() {
			return pkg.ErrInvalidGrant("authorization code expired or already used")
		}

		// Replay detection: if code was already used, revoke all tokens for the session
		if authCode.Used {
			if authCode.SessionID != nil {
				tx.RevokeAccessTokensBySession(*authCode.SessionID)
				tx.RevokeRefreshTokensBySession(*authCode.SessionID)
			}
			return pkg.ErrInvalidGrant("authorization code already used")
		}

		if authCode.ClientID != client.ID {
			return pkg.ErrInvalidGrant("client mismatch")
		}
		if authCode.RedirectURI != redirectURI {
			return pkg.ErrInvalidGrant("redirect_uri mismatch")
		}

		// PKCE validation
		if authCode.HasPKCE() {
			if codeVerifier == "" {
				return pkg.ErrInvalidGrant("code_verifier required")
			}
			if !verifyPKCE(codeVerifier, *authCode.CodeChallenge) {
				return pkg.ErrInvalidGrant("PKCE verification failed")
			}
		} else if client.IsPublic {
			return pkg.ErrInvalidRequest("PKCE required for public clients")
		}

		// Mark code as used
		if err := tx.MarkAuthCodeUsed(codeHash); err != nil {
			return pkg.ErrServerError("failed to consume authorization code")
		}

		// Issue tokens
		var nonce string
		if authCode.Nonce != nil {
			nonce = *authCode.Nonce
		}
		authTime := authCode.CreatedAt
		if authCode.AuthTime != nil {
			authTime = *authCode.AuthTime
		}
		var requestedClaims string
		if authCode.ClaimsParam != nil {
			requestedClaims = *authCode.ClaimsParam
		}
		acr, amr := computeACR(authCode.AuthMethods)
		resp, err = s.issueTokensWithOpts(tx, client, &authCode.UserID, authCode.SessionID, authCode.Scopes, issueOpts{
			nonce:           nonce,
			authTime:        authTime,
			audience:        authCode.Audience,
			requestedClaims: requestedClaims,
			acr:             acr,
			amr:             amr,
		})
		return err
	})

	if err != nil {
		return nil, err
	}
	return resp, nil
}

// --- Token Exchange: Client Credentials ---

func (s *Service) ExchangeClientCredentials(client *model.OAuthClient, scope, audience string) (*TokenResponse, error) {
	if client.IsPublic {
		return nil, pkg.ErrUnauthorizedClient("public clients cannot use client_credentials grant")
	}
	if !client.HasGrantType("client_credentials") {
		return nil, pkg.ErrUnauthorizedClient("client is not authorized for client_credentials grant")
	}

	var scopes []string
	var tokenAudience *string
	ttl := client.AccessTokenTTL

	if audience != "" && s.resourceValidator != nil {
		resource, err := s.resourceValidator.ValidateAudience(audience)
		if err != nil {
			return nil, err
		}
		resourceScopes, err := s.resourceValidator.ValidateClientScopes(client.ID, resource.ID, parseSpaceDelimited(scope))
		if err != nil {
			return nil, err
		}
		if len(resourceScopes) == 0 {
			return nil, pkg.ErrInvalidScope("client has no permissions for this resource")
		}
		scopes = resourceScopes
		tokenAudience = &audience
		ttl = resource.AccessTokenTTL
	} else {
		scopes = client.ValidateScopes(parseSpaceDelimited(scope))
	}

	rawToken, tokenHash, err := crypto.GenerateOpaqueToken()
	if err != nil {
		return nil, pkg.ErrServerError("failed to generate access token")
	}

	accessToken := &model.AccessToken{
		ID:        tokenHash,
		ClientID:  client.ID,
		Scopes:    pq.StringArray(scopes),
		Audience:  tokenAudience,
		ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}

	if err := s.repo.CreateAccessToken(accessToken); err != nil {
		return nil, pkg.ErrServerError("failed to store access token")
	}

	slog.Info("client_credentials token issued", "client_id", client.ID, "audience", audience)
	return &TokenResponse{
		AccessToken: rawToken,
		TokenType:   "Bearer",
		ExpiresIn:   ttl,
		Scope:       joinScopes(scopes),
	}, nil
}

// --- Token Exchange: Refresh Token ---

func (s *Service) ExchangeRefreshToken(client *model.OAuthClient, refreshTokenRaw, scope string) (*TokenResponse, error) {
	if !client.HasGrantType("refresh_token") {
		return nil, pkg.ErrUnauthorizedClient("client is not authorized for refresh_token grant")
	}

	rtHash := crypto.HashToken(refreshTokenRaw)

	var resp *TokenResponse
	err := s.repo.Transaction(func(tx RepositoryInterface) error {
		rt, err := tx.FindRefreshToken(rtHash)
		if err != nil || rt == nil {
			return pkg.ErrInvalidGrant("invalid refresh token")
		}

		if rt.ClientID != client.ID {
			return pkg.ErrInvalidGrant("token not issued to this client")
		}

		if rt.ExpiresAt.Before(time.Now()) {
			return pkg.ErrInvalidGrant("refresh token expired")
		}

		if rt.Revoked {
			return pkg.ErrInvalidGrant("refresh token revoked")
		}

		// Reuse detection: if already rotated, this is a potential theft
		if rt.WasRotated() {
			slog.Warn("refresh token reuse detected, revoking family",
				"family_id", rt.FamilyID, "user_id", rt.UserID)
			tx.RevokeRefreshTokenFamily(rt.FamilyID)
			return pkg.ErrInvalidGrant("token reuse detected")
		}

		// Validate scopes (must be subset)
		requestedScopes := parseSpaceDelimited(scope)
		grantedScopes := rt.Scopes
		if len(requestedScopes) > 0 {
			grantedScopes = pq.StringArray(filterScopes(requestedScopes, rt.Scopes))
			if len(grantedScopes) == 0 {
				return pkg.ErrInvalidScope("requested scopes exceed original grant")
			}
		}

		// Evaluate refresh policies (velocity, time-of-day, scope re-eval)
		if s.policyEvaluator != nil {
			var u *model.User
			if s.userService != nil {
				u, _ = s.userService.GetByID(rt.UserID)
			}
			roles, perms := s.loadRoles(rt.UserID)
			pInput := inputs.BuildRefreshInput(u, client, roles, perms, requestedScopes, []string(grantedScopes), rt.SessionID.String(), "")
			result, pErr := s.policyEvaluator.Evaluate(context.Background(), "refresh", pInput)
			if pErr != nil {
				slog.Warn("refresh policy evaluation failed", "error", pErr)
			} else if result != nil {
				if result.Deny {
					return pkg.ErrAccessDenied(result.DenyReason)
				}
				if result.Modify != nil {
					if narrowed, ok := readModifyScopes(result.Modify, grantedScopes); ok {
						grantedScopes = narrowed
						if len(grantedScopes) == 0 {
							return pkg.ErrAccessDenied("policy narrowed all scopes")
						}
					}
				}
			}
		}

		// Rotate: mark old RT
		if err := tx.RotateRefreshToken(rtHash); err != nil {
			return pkg.ErrServerError("failed to rotate refresh token")
		}

		// Revoke old access tokens linked to this RT
		tx.RevokeAccessTokensByRefreshToken(rtHash)

		// Issue new tokens (preserve audience from original token)
		resp, err = s.issueTokensWithOpts(tx, client, &rt.UserID, &rt.SessionID, grantedScopes, issueOpts{
			authTime: time.Now(),
			audience: rt.Audience,
		})
		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, err
	}
	return resp, nil
}

// --- Helpers ---

type issueOpts struct {
	nonce           string
	authTime        time.Time
	audience        *string
	resourceID      *uuid.UUID
	requestedClaims string
	acr             string
	amr             []string
}

func (s *Service) issueTokens(tx RepositoryInterface, client *model.OAuthClient, userID *uuid.UUID, sessionID *uuid.UUID, scopes pq.StringArray) (*TokenResponse, error) {
	return s.issueTokensWithOpts(tx, client, userID, sessionID, scopes, issueOpts{authTime: time.Now()})
}

func (s *Service) issueTokensWithOpts(tx RepositoryInterface, client *model.OAuthClient, userID *uuid.UUID, sessionID *uuid.UUID, scopes pq.StringArray, opts issueOpts) (*TokenResponse, error) {
	// Evaluate token issuance policies
	var policyExtraClaims map[string]any
	if s.policyEvaluator != nil && userID != nil {
		var u *model.User
		if s.userService != nil {
			u, _ = s.userService.GetByID(*userID)
		}
		roles, perms := s.loadRoles(*userID)
		pInput := inputs.BuildTokenIssuanceInput(client, u, roles, perms, []string(scopes), "")
		result, pErr := s.policyEvaluator.Evaluate(context.Background(), "token_issuance", pInput)
		if pErr != nil {
			slog.Warn("token issuance policy evaluation failed", "error", pErr)
		} else if result != nil {
			if result.Deny {
				return nil, pkg.ErrAccessDenied(result.DenyReason)
			}
			if result.Modify != nil {
				if n, ok := readModifyInt(result.Modify, "access_token_ttl"); ok {
					client.AccessTokenTTL = n
				}
				if n, ok := readModifyInt(result.Modify, "refresh_token_ttl"); ok {
					client.RefreshTokenTTL = n
				}
				if narrowed, ok := readModifyScopes(result.Modify, scopes); ok {
					scopes = narrowed
				}
				if extra, ok := result.Modify["claims"].(map[string]any); ok {
					policyExtraClaims = extra
				}
			}
		}
	}

	// Resolve resourceID from audience if needed
	if opts.audience != nil && opts.resourceID == nil && s.resourceValidator != nil {
		if res, err := s.resourceValidator.ValidateAudience(*opts.audience); err == nil && res != nil {
			opts.resourceID = &res.ID
		}
	}

	// Validate user scopes against role-resource permissions (if audience is set)
	if opts.resourceID != nil && userID != nil && s.resourceValidator != nil {
		userScopes, err := s.resourceValidator.ValidateUserScopes(*userID, *opts.resourceID, scopes)
		if err != nil {
			slog.Warn("user scope validation failed", "error", err)
		} else if len(userScopes) > 0 {
			scopes = pq.StringArray(userScopes)
		}
	}

	// Generate access token
	rawAT, atHash, err := crypto.GenerateOpaqueToken()
	if err != nil {
		return nil, pkg.ErrServerError("failed to generate access token")
	}

	// Generate refresh token
	rawRT, rtHash, err := crypto.GenerateOpaqueToken()
	if err != nil {
		return nil, pkg.ErrServerError("failed to generate refresh token")
	}

	familyID, _ := uuid.NewV7()

	refreshToken := &model.RefreshToken{
		ID:        rtHash,
		ClientID:  client.ID,
		UserID:    *userID,
		SessionID: *sessionID,
		Scopes:    scopes,
		Audience:  opts.audience,
		FamilyID:  familyID,
		ExpiresAt: time.Now().Add(time.Duration(client.RefreshTokenTTL) * time.Second),
	}

	if err := tx.CreateRefreshToken(refreshToken); err != nil {
		return nil, pkg.ErrServerError("failed to store refresh token")
	}

	accessToken := &model.AccessToken{
		ID:             atHash,
		ClientID:       client.ID,
		UserID:         userID,
		SessionID:      sessionID,
		RefreshTokenID: &rtHash,
		Scopes:         scopes,
		Audience:       opts.audience,
		ExpiresAt:      time.Now().Add(time.Duration(client.AccessTokenTTL) * time.Second),
	}

	if err := tx.CreateAccessToken(accessToken); err != nil {
		return nil, pkg.ErrServerError("failed to store access token")
	}

	resp := &TokenResponse{
		AccessToken:  rawAT,
		TokenType:    "Bearer",
		ExpiresIn:    client.AccessTokenTTL,
		RefreshToken: rawRT,
		Scope:        joinScopes(scopes),
	}

	// Generate ID token if openid scope is present
	if s.idTokenGen != nil && containsScope(scopes, "openid") && userID != nil {
		atHashValue := computeATHash(rawAT)
		authTime := opts.authTime
		if authTime.IsZero() {
			authTime = time.Now()
		}

		sectorID := ""
		if client.SectorIdentifierURI != nil {
			sectorID = *client.SectorIdentifierURI
		}

		idToken, err := s.idTokenGen.GenerateIDToken(IDTokenClaims{
			UserID:           *userID,
			ClientID:         client.ID,
			Scopes:           scopes,
			Nonce:            opts.nonce,
			AuthTime:         authTime,
			ATHash:           atHashValue,
			TTL:              time.Duration(client.IDTokenTTL) * time.Second,
			RequestedClaims:  opts.requestedClaims,
			ACR:              opts.acr,
			AMR:              opts.amr,
			SubjectType:      client.SubjectType,
			SectorIdentifier: sectorID,
			ExtraClaims:      policyExtraClaims,
		})
		if err != nil {
			slog.Warn("failed to generate ID token", "error", err)
		} else {
			resp.IDToken = idToken
		}
	}

	return resp, nil
}

func containsScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

func computeATHash(accessToken string) string {
	h := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(h[:16])
}

func verifyPKCE(codeVerifier, codeChallenge string) bool {
	h := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(codeChallenge)) == 1
}

func isValidResponseType(rt string) bool {
	switch rt {
	case "code", "code id_token", "code token", "code id_token token":
		return true
	}
	return false
}

func isHybridResponseType(rt string) bool {
	return rt != "code" && isValidResponseType(rt)
}

func responseTypeIncludes(rt, part string) bool {
	for _, p := range strings.Split(rt, " ") {
		if p == part {
			return true
		}
	}
	return false
}

func computeACR(authMethods []string) (string, []string) {
	if len(authMethods) == 0 {
		return "", nil
	}
	amr := make([]string, len(authMethods))
	copy(amr, authMethods)

	hasOTP := false
	for _, m := range authMethods {
		if m == "otp" {
			hasOTP = true
			break
		}
	}

	acr := "urn:orionauth:acr:pwd"
	if hasOTP {
		acr = "urn:orionauth:acr:mfa"
	}
	return acr, amr
}

// computeSessionState implements OIDC Session Management session_state calculation.
// session_state = SHA256(client_id + " " + origin + " " + session_id + " " + salt) + "." + salt
func computeSessionState(clientID, redirectURI, sessionID string) string {
	origin := extractOrigin(redirectURI)
	salt, _ := crypto.GenerateRandomString(16)
	data := clientID + " " + origin + " " + sessionID + " " + salt
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:]) + "." + salt
}

func extractOrigin(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	return u.Scheme + "://" + u.Host
}

func parseSpaceDelimited(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	for _, part := range splitBySpace(s) {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func splitBySpace(s string) []string {
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

func joinScopes(scopes []string) string {
	result := ""
	for i, s := range scopes {
		if i > 0 {
			result += " "
		}
		result += s
	}
	return result
}

func filterScopes(requested, allowed []string) []string {
	set := make(map[string]bool, len(allowed))
	for _, s := range allowed {
		set[s] = true
	}
	var result []string
	for _, r := range requested {
		if set[r] {
			result = append(result, r)
		}
	}
	return result
}
