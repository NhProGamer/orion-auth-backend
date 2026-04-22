package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"orion-auth-backend/config"
	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
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
}

// IDTokenClaims mirrors oidc.IDTokenClaims to avoid circular imports.
type IDTokenClaims struct {
	UserID   uuid.UUID
	ClientID uuid.UUID
	Scopes   []string
	Nonce    string
	AuthTime time.Time
	ATHash   string
	TTL      time.Duration
}

type Service struct {
	repo              RepositoryInterface
	userService       *user.Service
	sessionService    *session.Service
	hasher            *crypto.Argon2Hasher
	cfg               config.AuthConfig
	idTokenGen        IDTokenGenerator
	mfaValidator      MFAValidator
	policyEvaluator   PolicyEvaluator
	resourceValidator ResourceValidator
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

type InitAuthorizeResponse struct {
	RequestID       uuid.UUID     `json:"request_id"`
	ClientName      string        `json:"client_name"`
	ClientID        uuid.UUID     `json:"client_id"`
	ScopesRequested []string      `json:"scopes_requested"`
	RequiresLogin   bool          `json:"requires_login"`
	RequiresConsent bool          `json:"requires_consent"`
	Resource        *ResourceInfo `json:"resource,omitempty"`
}

func (s *Service) InitAuthorize(client *model.OAuthClient, redirectURI, responseType, scope, state, nonce, codeChallenge, codeChallengeMethod, audience string) (*InitAuthorizeResponse, error) {
	// Validate response_type
	if responseType != "code" && responseType != "token" {
		return nil, pkg.ErrUnsupportedResponseType("supported response_types: code, token")
	}

	// Validate redirect_uri
	if !client.HasRedirectURI(redirectURI) {
		return nil, pkg.ErrInvalidRequest("invalid redirect_uri")
	}

	// Validate grant type
	if !client.HasGrantType("authorization_code") {
		return nil, pkg.ErrUnauthorizedClient("client is not authorized for authorization_code grant")
	}

	// Validate PKCE for public clients
	if client.IsPublic && codeChallenge == "" {
		return nil, pkg.ErrInvalidRequest("PKCE (code_challenge) is required for public clients")
	}

	// Only S256 allowed
	if codeChallenge != "" && codeChallengeMethod != "S256" && codeChallengeMethod != "" {
		return nil, pkg.ErrInvalidRequest("only S256 code_challenge_method is supported")
	}
	if codeChallenge != "" && codeChallengeMethod == "" {
		codeChallengeMethod = "S256"
	}

	// Validate audience and scopes
	var validatedAudience *string
	var resourceInfo *ResourceInfo
	var scopes []string

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
		validatedAudience = &audience

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
		scopes = client.ValidateScopes(parseSpaceDelimited(scope))
		if len(scopes) == 0 {
			return nil, pkg.ErrInvalidScope("no valid scopes requested")
		}
	}

	// Create authorization request
	req := &model.AuthorizationRequest{
		ClientID:     client.ID,
		RedirectURI:  redirectURI,
		ResponseType: responseType,
		Scopes:       pq.StringArray(scopes),
		Audience:     validatedAudience,
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	}

	if state != "" {
		req.State = &state
	}
	if nonce != "" {
		req.Nonce = &nonce
	}
	if codeChallenge != "" {
		req.CodeChallenge = &codeChallenge
		req.CodeChallengeMethod = &codeChallengeMethod
	}

	if err := s.repo.CreateAuthRequest(req); err != nil {
		slog.Error("failed to create auth request", "error", err)
		return nil, pkg.ErrServerError("failed to create authorization request")
	}

	return &InitAuthorizeResponse{
		RequestID:       req.ID,
		ClientName:      client.Name,
		ClientID:        client.ID,
		ScopesRequested: scopes,
		RequiresLogin:   true,
		RequiresConsent: !client.IsFirstParty,
		Resource:        resourceInfo,
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
		pInput := map[string]any{
			"user": map[string]any{
				"id":             u.ID.String(),
				"email":          u.Email,
				"email_verified": u.EmailVerified,
				"active":         u.Active,
			},
			"ip_address": ipAddress,
			"user_agent": userAgent,
		}
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
	var needsMFA bool
	if s.mfaValidator != nil {
		hasMFA, _ := s.mfaValidator.HasMFA(u.ID)
		needsMFA = hasMFA
	}

	req.UserID = &u.ID
	if needsMFA {
		// Don't mark as authenticated yet — MFA step required
	} else {
		req.Authenticated = true
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
	RedirectURI string `json:"redirect_uri"`
	Code        string `json:"code,omitempty"`
	State       string `json:"state,omitempty"`
	// Implicit flow fields
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
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

	// Implicit flow: response_type=token → return access token directly
	if req.ResponseType == "token" {
		return s.completeImplicit(req, &sess.ID)
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

	if err := s.repo.CreateAuthCode(authCode); err != nil {
		return nil, pkg.ErrServerError("failed to create authorization code")
	}

	resp := &AuthorizeConsentResponse{
		RedirectURI: req.RedirectURI,
		Code:        rawCode,
	}
	if req.State != nil {
		resp.State = *req.State
	}

	slog.Info("authorization code issued", "client_id", req.ClientID, "user_id", req.UserID)
	return resp, nil
}

// completeImplicit handles the implicit flow (deprecated, no refresh token).
func (s *Service) completeImplicit(req *model.AuthorizationRequest, sessionID *uuid.UUID) (*AuthorizeConsentResponse, error) {
	// Look up client for TTL
	client, err := s.repo.findClient(req.ClientID.String())
	if err != nil {
		return nil, pkg.ErrServerError("failed to find client")
	}

	rawAT, atHash, err := crypto.GenerateOpaqueToken()
	if err != nil {
		return nil, pkg.ErrServerError("failed to generate access token")
	}

	accessToken := &model.AccessToken{
		ID:        atHash,
		ClientID:  req.ClientID,
		UserID:    req.UserID,
		SessionID: sessionID,
		Scopes:    req.Scopes,
		ExpiresAt: time.Now().Add(time.Duration(client.AccessTokenTTL) * time.Second),
	}

	if err := s.repo.CreateAccessToken(accessToken); err != nil {
		return nil, pkg.ErrServerError("failed to store access token")
	}

	resp := &AuthorizeConsentResponse{
		RedirectURI: req.RedirectURI,
		AccessToken: rawAT,
		TokenType:   "Bearer",
		ExpiresIn:   client.AccessTokenTTL,
	}
	if req.State != nil {
		resp.State = *req.State
	}

	slog.Info("implicit token issued (deprecated flow)", "client_id", req.ClientID, "user_id", req.UserID)
	return resp, nil
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
		resp, err = s.issueTokensWithOpts(tx, client, &authCode.UserID, authCode.SessionID, authCode.Scopes, issueOpts{
			nonce:    nonce,
			authTime: authCode.CreatedAt,
			audience: authCode.Audience,
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
	nonce    string
	authTime time.Time
	audience *string
}

func (s *Service) issueTokens(tx RepositoryInterface, client *model.OAuthClient, userID *uuid.UUID, sessionID *uuid.UUID, scopes pq.StringArray) (*TokenResponse, error) {
	return s.issueTokensWithOpts(tx, client, userID, sessionID, scopes, issueOpts{authTime: time.Now()})
}

func (s *Service) issueTokensWithOpts(tx RepositoryInterface, client *model.OAuthClient, userID *uuid.UUID, sessionID *uuid.UUID, scopes pq.StringArray, opts issueOpts) (*TokenResponse, error) {
	// Evaluate token issuance policies
	if s.policyEvaluator != nil && userID != nil {
		var u *model.User
		if s.userService != nil {
			u, _ = s.userService.GetByID(*userID)
		}
		pInput := map[string]any{
			"client": map[string]any{
				"id":             client.ID.String(),
				"name":           client.Name,
				"is_public":      client.IsPublic,
				"is_first_party": client.IsFirstParty,
			},
			"scopes": []string(scopes),
		}
		if u != nil {
			pInput["user"] = map[string]any{
				"id":             u.ID.String(),
				"email":          u.Email,
				"email_verified": u.EmailVerified,
				"active":         u.Active,
			}
		}
		result, pErr := s.policyEvaluator.Evaluate(context.Background(), "token_issuance", pInput)
		if pErr != nil {
			slog.Warn("token issuance policy evaluation failed", "error", pErr)
		} else if result != nil {
			if result.Deny {
				return nil, pkg.ErrAccessDenied(result.DenyReason)
			}
			if result.Modify != nil {
				if ttl, ok := result.Modify["access_token_ttl"]; ok {
					if v, ok := ttl.(json.Number); ok {
						if n, err := v.Int64(); err == nil {
							client.AccessTokenTTL = int(n)
						}
					} else if v, ok := ttl.(float64); ok {
						client.AccessTokenTTL = int(v)
					}
				}
				if ttl, ok := result.Modify["refresh_token_ttl"]; ok {
					if v, ok := ttl.(json.Number); ok {
						if n, err := v.Int64(); err == nil {
							client.RefreshTokenTTL = int(n)
						}
					} else if v, ok := ttl.(float64); ok {
						client.RefreshTokenTTL = int(v)
					}
				}
			}
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

		idToken, err := s.idTokenGen.GenerateIDToken(IDTokenClaims{
			UserID:   *userID,
			ClientID: client.ID,
			Scopes:   scopes,
			Nonce:    opts.nonce,
			AuthTime: authTime,
			ATHash:   atHashValue,
			TTL:      time.Duration(client.IDTokenTTL) * time.Second,
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
