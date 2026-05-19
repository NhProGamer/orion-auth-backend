package oidc

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"

	appCrypto "orion-auth-backend/crypto"
	"orion-auth-backend/model"
	"orion-auth-backend/rbac"
	"orion-auth-backend/user"
)

// SessionRevoker is an interface to avoid circular imports with the session package.
type SessionRevoker interface {
	RevokeAll(userID uuid.UUID, currentSessionID *uuid.UUID) (int64, error)
}

// ClientFinder is an interface for looking up OAuth clients.
type ClientFinder interface {
	FindActiveByID(id uuid.UUID) (*model.OAuthClient, error)
	FindClientsWithBackchannelLogout(userID uuid.UUID) ([]model.OAuthClient, error)
	FindClientsWithFrontchannelLogout(userID uuid.UUID) ([]model.OAuthClient, error)
}

type Service struct {
	db             *gorm.DB
	userService    *user.Service
	rbacService    *rbac.Service
	sessionRevoker SessionRevoker
	clientFinder   ClientFinder
	issuer         string
	pairwiseSalt   string

	mu         sync.RWMutex
	activeKey  *model.SigningKey
	privateKey *rsa.PrivateKey
	allKeys    []model.SigningKey
}

func (s *Service) SetRBACService(rs *rbac.Service) {
	s.rbacService = rs
}

func (s *Service) SetSessionRevoker(sr SessionRevoker) {
	s.sessionRevoker = sr
}

func (s *Service) SetClientFinder(cf ClientFinder) {
	s.clientFinder = cf
}

func NewService(db *gorm.DB, userService *user.Service, issuer string, pairwiseSalt string) *Service {
	return &Service{
		db:           db,
		userService:  userService,
		issuer:       issuer,
		pairwiseSalt: pairwiseSalt,
	}
}

// EnsureSigningKey loads or creates the active signing key.
func (s *Service) EnsureSigningKey() error {
	var key model.SigningKey
	err := s.db.Where("active = TRUE").Order("created_at DESC").First(&key).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		slog.Info("no active signing key found, generating new one")
		return s.RotateKey()
	}
	if err != nil {
		return err
	}

	privKey, err := appCrypto.ParseRSAPrivateKey(key.PrivateKeyPEM)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.activeKey = &key
	s.privateKey = privKey
	s.mu.Unlock()

	s.loadAllKeys()
	slog.Info("signing key loaded", "kid", key.ID)
	return nil
}

// RotateKey generates a new signing key and deactivates the old one.
func (s *Service) RotateKey() error {
	privPEM, pubPEM, err := appCrypto.GenerateRSAKeyPair()
	if err != nil {
		return err
	}

	id, err := uuid.NewV7()
	if err != nil {
		return err
	}

	// Deactivate old keys (keep them for verification with expiry)
	gracePeriod := time.Now().Add(24 * time.Hour)
	s.db.Model(&model.SigningKey{}).Where("active = TRUE").Updates(map[string]any{
		"active":     false,
		"expires_at": gracePeriod,
	})

	key := model.SigningKey{
		ID:            id,
		PrivateKeyPEM: privPEM,
		PublicKeyPEM:  pubPEM,
		Algorithm:     "RS256",
		Active:        true,
	}

	if err := s.db.Create(&key).Error; err != nil {
		return err
	}

	privKey, err := appCrypto.ParseRSAPrivateKey(privPEM)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.activeKey = &key
	s.privateKey = privKey
	s.mu.Unlock()

	s.loadAllKeys()
	slog.Info("signing key rotated", "kid", key.ID)
	return nil
}

func (s *Service) loadAllKeys() {
	var keys []model.SigningKey
	s.db.Where("active = TRUE OR (expires_at IS NOT NULL AND expires_at > ?)", time.Now()).
		Order("created_at DESC").Find(&keys)

	s.mu.Lock()
	s.allKeys = keys
	s.mu.Unlock()
}

// --- ID Token Generation ---

type IDTokenClaims struct {
	UserID           uuid.UUID
	ClientID         uuid.UUID
	Scopes           []string
	Nonce            string
	AuthTime         time.Time
	ATHash           string // access token hash
	CHash            string // authorization code hash (hybrid flows)
	SHash            string // state hash (hybrid flows)
	TTL              time.Duration
	RequestedClaims  string // JSON claims parameter from the authorization request
	ACR              string
	AMR              []string
	SubjectType      string // "public" or "pairwise"
	SectorIdentifier string // sector identifier for pairwise sub
	ExtraClaims      map[string]any
}

func (s *Service) GenerateIDToken(claims IDTokenClaims) (string, error) {
	s.mu.RLock()
	key := s.activeKey
	privKey := s.privateKey
	s.mu.RUnlock()

	if key == nil || privKey == nil {
		return "", errors.New("no active signing key")
	}

	now := time.Now()

	sub := claims.UserID.String()
	if claims.SubjectType == "pairwise" && s.pairwiseSalt != "" {
		sector := claims.SectorIdentifier
		if sector == "" {
			sector = claims.ClientID.String()
		}
		sub = ComputePairwiseSub(sector, claims.UserID, s.pairwiseSalt)
	}

	jwtClaims := jwt.MapClaims{
		"iss":       s.issuer,
		"sub":       sub,
		"aud":       claims.ClientID.String(),
		"exp":       now.Add(claims.TTL).Unix(),
		"iat":       now.Unix(),
		"auth_time": claims.AuthTime.Unix(),
	}

	if claims.Nonce != "" {
		jwtClaims["nonce"] = claims.Nonce
	}

	if claims.ATHash != "" {
		jwtClaims["at_hash"] = claims.ATHash
	}

	if claims.CHash != "" {
		jwtClaims["c_hash"] = claims.CHash
	}
	if claims.SHash != "" {
		jwtClaims["s_hash"] = claims.SHash
	}

	if claims.ACR != "" {
		jwtClaims["acr"] = claims.ACR
	}
	if len(claims.AMR) > 0 {
		jwtClaims["amr"] = claims.AMR
	}

	// Add user claims based on scopes
	u, err := s.userService.GetByID(claims.UserID)
	if err == nil && u != nil {
		userClaims := u.OIDCClaims(claims.Scopes)
		for k, v := range userClaims {
			if k != "sub" { // don't override sub
				jwtClaims[k] = v
			}
		}
	}

	s.enrichClaimsWithRoles(claims.UserID, claims.Scopes, jwtClaims)

	// Inject extra claims from token_issuance policy modify. Reserved JWT/OIDC
	// claim names are protected from override to keep tokens spec-conformant.
	if len(claims.ExtraClaims) > 0 {
		applyExtraClaims(jwtClaims, claims.ExtraClaims)
	}

	// Honor the claims parameter (OIDC Core Section 5.5)
	if claims.RequestedClaims != "" && u != nil {
		s.applyRequestedClaims(claims.RequestedClaims, "id_token", u, jwtClaims)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims)
	token.Header["kid"] = key.ID.String()

	return token.SignedString(privKey)
}

// reservedIDTokenClaims is the set of claim names a policy may not override
// via modify.claims — these are spec-mandated or computed by the issuer.
var reservedIDTokenClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "iat": true,
	"auth_time": true, "nonce": true, "at_hash": true, "c_hash": true,
	"s_hash": true, "acr": true, "amr": true,
}

// applyExtraClaims merges extra claims into jwtClaims, skipping reserved keys.
func applyExtraClaims(jwtClaims jwt.MapClaims, extra map[string]any) {
	for k, v := range extra {
		if reservedIDTokenClaims[k] {
			continue
		}
		jwtClaims[k] = v
	}
}

// applyRequestedClaims parses the claims parameter JSON and adds requested claims
// for the given target ("id_token" or "userinfo") to the claims map.
func (s *Service) applyRequestedClaims(requestedClaimsJSON, target string, u *model.User, claims jwt.MapClaims) {
	var parsed map[string]map[string]any
	if err := json.Unmarshal([]byte(requestedClaimsJSON), &parsed); err != nil {
		return
	}

	targetClaims, ok := parsed[target]
	if !ok {
		return
	}

	// Map of all available user claims
	allClaims := u.OIDCClaims([]string{"openid", "profile", "email", "phone", "address"})

	for claimName := range targetClaims {
		if _, alreadySet := claims[claimName]; alreadySet {
			continue
		}
		if val, available := allClaims[claimName]; available {
			claims[claimName] = val
		}
	}
}

// ValidateIDToken parses and validates an ID token, returning the subject (user ID).
// Used for id_token_hint validation in prompt=none and end_session flows.
func (s *Service) ValidateIDToken(tokenString string) (uuid.UUID, error) {
	s.mu.RLock()
	keys := s.allKeys
	s.mu.RUnlock()

	// Build a key function that tries all known keys
	keyFunc := func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unexpected signing method")
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing kid in token header")
		}

		for _, k := range keys {
			if k.ID.String() == kid {
				pubKey, err := appCrypto.ParseRSAPublicKey(k.PublicKeyPEM)
				if err != nil {
					return nil, err
				}
				return pubKey, nil
			}
		}
		return nil, errors.New("unknown signing key")
	}

	token, err := jwt.Parse(tokenString, keyFunc,
		jwt.WithIssuer(s.issuer),
		jwt.WithValidMethods([]string{"RS256"}),
	)
	if err != nil {
		return uuid.Nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return uuid.Nil, errors.New("invalid token claims")
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return uuid.Nil, errors.New("missing sub claim")
	}

	userID, err := uuid.Parse(sub)
	if err != nil {
		return uuid.Nil, errors.New("invalid sub claim")
	}

	return userID, nil
}

// ComputeATHash computes the at_hash claim for an access token.
func ComputeATHash(accessToken string) string {
	h := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(h[:16]) // left half of SHA-256
}

// --- JWKS ---

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func (s *Service) GetJWKS() JWKS {
	s.mu.RLock()
	keys := s.allKeys
	s.mu.RUnlock()

	jwks := JWKS{Keys: make([]JWK, 0, len(keys))}

	for _, key := range keys {
		pubKey, err := appCrypto.ParseRSAPublicKey(key.PublicKeyPEM)
		if err != nil {
			slog.Warn("failed to parse public key", "kid", key.ID, "error", err)
			continue
		}

		jwks.Keys = append(jwks.Keys, JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: key.Algorithm,
			Kid: key.ID.String(),
			N:   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
		})
	}

	return jwks
}

// --- Discovery ---

type OpenIDConfiguration struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	JwksURI                                    string   `json:"jwks_uri"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	DeviceAuthorizationEndpoint                string   `json:"device_authorization_endpoint"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported,omitempty"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	BackchannelLogoutSupported                 bool     `json:"backchannel_logout_supported"`
	BackchannelLogoutSessionSupported          bool     `json:"backchannel_logout_session_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
	PushedAuthorizationRequestEndpoint         string   `json:"pushed_authorization_request_endpoint,omitempty"`
	FrontchannelLogoutSupported                bool     `json:"frontchannel_logout_supported"`
	FrontchannelLogoutSessionSupported         bool     `json:"frontchannel_logout_session_supported"`
	CheckSessionIframe                         string   `json:"check_session_iframe,omitempty"`
	UserinfoSigningAlgValuesSupported          []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	RegistrationEndpoint                       string   `json:"registration_endpoint,omitempty"`
}

func (s *Service) GetDiscovery() OpenIDConfiguration {
	return OpenIDConfiguration{
		Issuer:                            s.issuer,
		AuthorizationEndpoint:             s.issuer + "/ui/authorize",
		TokenEndpoint:                     s.issuer + "/token",
		UserinfoEndpoint:                  s.issuer + "/userinfo",
		JwksURI:                           s.issuer + "/.well-known/jwks.json",
		IntrospectionEndpoint:             s.issuer + "/introspect",
		RevocationEndpoint:                s.issuer + "/revoke",
		DeviceAuthorizationEndpoint:       s.issuer + "/device_authorization",
		EndSessionEndpoint:                s.issuer + "/end_session",
		ResponseTypesSupported:            []string{"code", "code id_token", "code token", "code id_token token"},
		GrantTypesSupported:               []string{"authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		SubjectTypesSupported:             []string{"public", "pairwise"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		ScopesSupported:                   []string{"openid", "profile", "email", "phone", "address", "roles", "offline_access"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt", "none"},
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash",
			"acr", "amr",
			"name", "given_name", "family_name", "middle_name", "nickname",
			"preferred_username", "profile", "picture", "website",
			"gender", "birthdate", "zoneinfo", "locale",
			"email", "email_verified",
			"phone_number", "phone_number_verified",
			"address", "updated_at", "roles", "groups",
		},
		CodeChallengeMethodsSupported:              []string{"S256"},
		ResponseModesSupported:                     []string{"query", "fragment", "form_post"},
		RequestParameterSupported:                  true,
		RequestURIParameterSupported:               true,
		RequestObjectSigningAlgValuesSupported:     []string{"RS256", "RS384", "RS512", "PS256", "ES256", "ES384"},
		ClaimsParameterSupported:                   true,
		BackchannelLogoutSupported:                 true,
		BackchannelLogoutSessionSupported:          true,
		AuthorizationResponseIssParameterSupported: true,
		PushedAuthorizationRequestEndpoint:         s.issuer + "/par",
		FrontchannelLogoutSupported:                true,
		FrontchannelLogoutSessionSupported:         true,
		CheckSessionIframe:                         s.issuer + "/check_session",
		UserinfoSigningAlgValuesSupported:          []string{"RS256"},
		RegistrationEndpoint:                       s.issuer + "/register",
	}
}

// OAuthAuthorizationServerMetadata is the RFC 8414 metadata document for the
// OAuth 2.0 authorization server, exposed at
// /.well-known/oauth-authorization-server. It overlaps heavily with the OIDC
// discovery document but omits OIDC-specific fields (subject_types_supported,
// id_token_*, userinfo_endpoint, end_session, *channel_logout, claims_supported)
// so that pure OAuth resource servers that probe this URL get only the
// metadata that applies to them.
type OAuthAuthorizationServerMetadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	JwksURI                                    string   `json:"jwks_uri"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	DeviceAuthorizationEndpoint                string   `json:"device_authorization_endpoint"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported,omitempty"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
	PushedAuthorizationRequestEndpoint         string   `json:"pushed_authorization_request_endpoint,omitempty"`
	RegistrationEndpoint                       string   `json:"registration_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported  []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
}

// GetOAuthAuthorizationServerMetadata returns the RFC 8414 metadata document.
// Values mirror GetDiscovery() for fields that overlap, so changes stay in
// sync as long as both methods are touched together.
func (s *Service) GetOAuthAuthorizationServerMetadata() OAuthAuthorizationServerMetadata {
	authMethods := []string{"client_secret_basic", "client_secret_post", "private_key_jwt", "client_secret_jwt", "none"}
	return OAuthAuthorizationServerMetadata{
		Issuer:                                     s.issuer,
		AuthorizationEndpoint:                      s.issuer + "/ui/authorize",
		TokenEndpoint:                              s.issuer + "/token",
		JwksURI:                                    s.issuer + "/.well-known/jwks.json",
		IntrospectionEndpoint:                      s.issuer + "/introspect",
		RevocationEndpoint:                         s.issuer + "/revoke",
		DeviceAuthorizationEndpoint:                s.issuer + "/device_authorization",
		ResponseTypesSupported:                     []string{"code", "code id_token", "code token", "code id_token token"},
		GrantTypesSupported:                        []string{"authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		ScopesSupported:                            []string{"openid", "profile", "email", "phone", "address", "roles", "offline_access"},
		TokenEndpointAuthMethodsSupported:          authMethods,
		CodeChallengeMethodsSupported:              []string{"S256"},
		ResponseModesSupported:                     []string{"query", "fragment", "form_post"},
		RequestParameterSupported:                  true,
		RequestURIParameterSupported:               true,
		RequestObjectSigningAlgValuesSupported:     []string{"RS256", "RS384", "RS512", "PS256", "ES256", "ES384"},
		AuthorizationResponseIssParameterSupported: true,
		PushedAuthorizationRequestEndpoint:         s.issuer + "/par",
		RegistrationEndpoint:                       s.issuer + "/register",
		IntrospectionEndpointAuthMethodsSupported:  authMethods,
		RevocationEndpointAuthMethodsSupported:     authMethods,
	}
}

// --- UserInfo ---

func (s *Service) GetUserInfo(userID uuid.UUID, clientID uuid.UUID, scopes []string) (map[string]any, error) {
	u, err := s.userService.GetByID(userID)
	if err != nil {
		return nil, err
	}
	claims := u.OIDCClaims(scopes)
	s.enrichClaimsWithRoles(userID, scopes, claims)

	// Apply pairwise subject if the client uses it
	if s.clientFinder != nil && clientID != uuid.Nil {
		if client, err := s.clientFinder.FindActiveByID(clientID); err == nil && client.SubjectType == "pairwise" {
			sector := ""
			if client.SectorIdentifierURI != nil {
				sector = *client.SectorIdentifierURI
			}
			if sector == "" {
				sector = clientID.String()
			}
			claims["sub"] = ComputePairwiseSub(sector, userID, s.pairwiseSalt)
		}
	}

	return claims, nil
}

// GenerateUserInfoJWT signs the UserInfo claims as a JWT (RS256).
func (s *Service) GenerateUserInfoJWT(claims map[string]any, clientID uuid.UUID) (string, error) {
	s.mu.RLock()
	key := s.activeKey
	privKey := s.privateKey
	s.mu.RUnlock()

	if key == nil || privKey == nil {
		return "", errors.New("no active signing key")
	}

	now := time.Now()
	jwtClaims := jwt.MapClaims{
		"iss": s.issuer,
		"aud": clientID.String(),
		"iat": now.Unix(),
	}
	for k, v := range claims {
		jwtClaims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims)
	token.Header["kid"] = key.ID.String()

	return token.SignedString(privKey)
}

func (s *Service) enrichClaimsWithRoles(userID uuid.UUID, scopes []string, claims map[string]any) {
	if s.rbacService == nil {
		return
	}
	for _, scope := range scopes {
		if scope == "roles" {
			roles, err := s.rbacService.GetUserRoles(userID)
			if err != nil {
				slog.Error("failed to fetch roles for claims", "user_id", userID, "error", err)
				return
			}
			names := make([]string, len(roles))
			for i, r := range roles {
				names[i] = r.Name
			}
			claims["roles"] = names
			claims["groups"] = names
			return
		}
	}
}

// ComputePairwiseSub computes a pairwise pseudonymous subject identifier.
// It uses HMAC-SHA256 with a server salt, the sector identifier, and the user ID.
func ComputePairwiseSub(sectorIdentifier string, userID uuid.UUID, salt string) string {
	key := []byte(salt)
	data := sectorIdentifier + userID.String()
	h := sha256.Sum256(append(key, []byte(data)...))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// --- End Session (RP-Initiated Logout) ---

type EndSessionParams struct {
	IDTokenHint           string
	PostLogoutRedirectURI string
	State                 string
	ClientID              string
}

type EndSessionResponse struct {
	RedirectURI            string   `json:"redirect_uri,omitempty"`
	LoggedOut              bool     `json:"logged_out"`
	FrontchannelLogoutURIs []string `json:"frontchannel_logout_uris,omitempty"`
}

func (s *Service) EndSession(params EndSessionParams) (*EndSessionResponse, error) {
	var userID *uuid.UUID

	// Validate id_token_hint if provided
	if params.IDTokenHint != "" {
		uid, err := s.ValidateIDToken(params.IDTokenHint)
		if err != nil {
			slog.Warn("invalid id_token_hint in end_session", "error", err)
			// Per spec, invalid id_token_hint should not prevent logout display
		} else {
			userID = &uid
		}
	}

	// Revoke all sessions for the identified user
	if userID != nil && s.sessionRevoker != nil {
		if _, err := s.sessionRevoker.RevokeAll(*userID, nil); err != nil {
			slog.Error("failed to revoke sessions during end_session", "user_id", userID, "error", err)
		}
	}

	// Back-Channel Logout: notify RPs asynchronously
	if userID != nil && s.clientFinder != nil {
		s.dispatchBackchannelLogout(*userID)
	}

	resp := &EndSessionResponse{LoggedOut: true}

	// Front-Channel Logout: collect iframe URLs for RPs with active consents for this user
	if userID != nil && s.clientFinder != nil {
		fcClients, _ := s.clientFinder.FindClientsWithFrontchannelLogout(*userID)
		for _, c := range fcClients {
			if c.FrontchannelLogoutURI != nil {
				resp.FrontchannelLogoutURIs = append(resp.FrontchannelLogoutURIs, *c.FrontchannelLogoutURI)
			}
		}
	}

	// Validate post_logout_redirect_uri
	if params.PostLogoutRedirectURI != "" {
		validRedirect := false

		// Look up client to validate the post_logout_redirect_uri
		if params.ClientID != "" && s.clientFinder != nil {
			clientUUID, err := uuid.Parse(params.ClientID)
			if err == nil {
				client, err := s.clientFinder.FindActiveByID(clientUUID)
				if err == nil && client != nil && client.HasPostLogoutRedirectURI(params.PostLogoutRedirectURI) {
					validRedirect = true
				}
			}
		}

		if validRedirect {
			redirectURI := params.PostLogoutRedirectURI
			if params.State != "" {
				redirectURI += "?state=" + params.State
			}
			resp.RedirectURI = redirectURI
		}
	}

	return resp, nil
}

// GenerateLogoutToken creates a logout_token JWT for Back-Channel Logout.
// If sessionRequired is true and sessionID is provided, the sid claim is included.
func (s *Service) GenerateLogoutToken(userID, clientID uuid.UUID, sessionRequired bool, sessionID *uuid.UUID) (string, error) {
	s.mu.RLock()
	key := s.activeKey
	privKey := s.privateKey
	s.mu.RUnlock()

	if key == nil || privKey == nil {
		return "", errors.New("no active signing key")
	}

	jti, _ := uuid.NewV7()
	now := time.Now()

	claims := jwt.MapClaims{
		"iss": s.issuer,
		"sub": userID.String(),
		"aud": clientID.String(),
		"iat": now.Unix(),
		"jti": jti.String(),
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}

	if sessionRequired && sessionID != nil {
		claims["sid"] = sessionID.String()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = key.ID.String()

	return token.SignedString(privKey)
}

// dispatchBackchannelLogout sends logout_tokens to all RPs with backchannel_logout_uri.
func (s *Service) dispatchBackchannelLogout(userID uuid.UUID) {
	clients, err := s.clientFinder.FindClientsWithBackchannelLogout(userID)
	if err != nil {
		slog.Error("failed to find clients for backchannel logout", "user_id", userID, "error", err)
		return
	}

	for _, client := range clients {
		if client.BackchannelLogoutURI == nil {
			continue
		}
		go func(c model.OAuthClient) {
			logoutToken, err := s.GenerateLogoutToken(userID, c.ID, c.BackchannelLogoutSessionReq, nil)
			if err != nil {
				slog.Error("failed to generate logout token", "client_id", c.ID, "error", err)
				return
			}

			httpClient := &http.Client{Timeout: 5 * time.Second}
			resp, err := httpClient.PostForm(*c.BackchannelLogoutURI, url.Values{
				"logout_token": {logoutToken},
			})
			if err != nil {
				slog.Warn("backchannel logout request failed", "client_id", c.ID, "uri", *c.BackchannelLogoutURI, "error", err)
				return
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				slog.Info("backchannel logout succeeded", "client_id", c.ID)
			} else {
				slog.Warn("backchannel logout returned non-200", "client_id", c.ID, "status", resp.StatusCode)
			}
		}(client)
	}
}
