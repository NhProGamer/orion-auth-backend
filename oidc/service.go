package oidc

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"math/big"
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

type Service struct {
	db          *gorm.DB
	userService *user.Service
	rbacService *rbac.Service
	issuer      string

	mu         sync.RWMutex
	activeKey  *model.SigningKey
	privateKey *rsa.PrivateKey
	allKeys    []model.SigningKey
}

func (s *Service) SetRBACService(rs *rbac.Service) {
	s.rbacService = rs
}

func NewService(db *gorm.DB, userService *user.Service, issuer string) *Service {
	return &Service{
		db:          db,
		userService: userService,
		issuer:      issuer,
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
	UserID   uuid.UUID
	ClientID uuid.UUID
	Scopes   []string
	Nonce    string
	AuthTime time.Time
	ATHash   string // access token hash
	TTL      time.Duration
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
	jwtClaims := jwt.MapClaims{
		"iss":       s.issuer,
		"sub":       claims.UserID.String(),
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

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims)
	token.Header["kid"] = key.ID.String()

	return token.SignedString(privKey)
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
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	JwksURI                          string   `json:"jwks_uri"`
	IntrospectionEndpoint            string   `json:"introspection_endpoint"`
	RevocationEndpoint               string   `json:"revocation_endpoint"`
	DeviceAuthorizationEndpoint      string   `json:"device_authorization_endpoint"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
}

func (s *Service) GetDiscovery() OpenIDConfiguration {
	return OpenIDConfiguration{
		Issuer:                           s.issuer,
		AuthorizationEndpoint:            s.issuer + "/ui/authorize",
		TokenEndpoint:                    s.issuer + "/token",
		UserinfoEndpoint:                 s.issuer + "/userinfo",
		JwksURI:                          s.issuer + "/.well-known/jwks.json",
		IntrospectionEndpoint:            s.issuer + "/introspect",
		RevocationEndpoint:               s.issuer + "/revoke",
		DeviceAuthorizationEndpoint:      s.issuer + "/device_authorization",
		ResponseTypesSupported:           []string{"code"},
		GrantTypesSupported:              []string{"authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid", "profile", "email", "roles", "offline_access"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		ClaimsSupported:                  []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash", "name", "email", "email_verified", "picture", "phone_number", "updated_at", "roles", "groups"},
		CodeChallengeMethodsSupported:    []string{"S256"},
	}
}

// --- UserInfo ---

func (s *Service) GetUserInfo(userID uuid.UUID, scopes []string) (map[string]any, error) {
	u, err := s.userService.GetByID(userID)
	if err != nil {
		return nil, err
	}
	claims := u.OIDCClaims(scopes)
	s.enrichClaimsWithRoles(userID, scopes, claims)
	return claims, nil
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
