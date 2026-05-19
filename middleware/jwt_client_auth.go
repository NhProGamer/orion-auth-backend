package middleware

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	appCrypto "orion-auth-backend/crypto"
)

// JWKSCache caches remote JWKS documents with a TTL.
type JWKSCache struct {
	mu      sync.RWMutex
	entries map[string]*jwksCacheEntry
}

type jwksCacheEntry struct {
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

const jwksCacheTTL = 5 * time.Minute

func NewJWKSCache() *JWKSCache {
	return &JWKSCache{entries: make(map[string]*jwksCacheEntry)}
}

// GetKey returns the RSA public key for the given kid from the remote JWKS URI.
func (c *JWKSCache) GetKey(jwksURI, kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	entry, ok := c.entries[jwksURI]
	c.mu.RUnlock()

	if ok && time.Since(entry.fetchedAt) < jwksCacheTTL {
		if key, found := entry.keys[kid]; found {
			return key, nil
		}
	}

	keys, err := fetchJWKS(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", jwksURI, err)
	}

	c.mu.Lock()
	c.entries[jwksURI] = &jwksCacheEntry{keys: keys, fetchedAt: time.Now()}
	c.mu.Unlock()

	key, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("key %s not found in JWKS", kid)
	}
	return key, nil
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func fetchJWKS(jwksURI string) (map[string]*rsa.PublicKey, error) {
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Get(jwksURI)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, err
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		pubKey, err := appCrypto.ParseJWKToRSAPublicKey(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = pubKey
	}
	return keys, nil
}

// validateAssertionCommonClaims runs the RFC 7523 §3 claim checks that are
// independent of the signing algorithm (sub, iss, aud, jti, exp). It returns
// the parsed unverified token so callers can dispatch to a per-alg verifier.
func validateAssertionCommonClaims(assertion, tokenEndpoint string) (*jwt.Token, uuid.UUID, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	unverified, _, err := parser.ParseUnverified(assertion, jwt.MapClaims{})
	if err != nil {
		return nil, uuid.Nil, errors.New("malformed client assertion JWT")
	}

	claims, ok := unverified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, uuid.Nil, errors.New("invalid JWT claims")
	}

	sub, err := claims.GetSubject()
	if err != nil || sub == "" {
		return nil, uuid.Nil, errors.New("missing sub claim in client assertion")
	}
	clientID, err := uuid.Parse(sub)
	if err != nil {
		return nil, uuid.Nil, errors.New("invalid client_id in sub claim")
	}

	iss, err := claims.GetIssuer()
	if err != nil || iss != sub {
		return nil, uuid.Nil, errors.New("iss must equal sub in client assertion")
	}

	aud, err := claims.GetAudience()
	if err != nil {
		return nil, uuid.Nil, errors.New("missing aud claim")
	}
	audValid := false
	for _, a := range aud {
		if a == tokenEndpoint {
			audValid = true
			break
		}
	}
	if !audValid {
		return nil, uuid.Nil, errors.New("aud must contain the token endpoint URL")
	}

	if jti, _ := claims["jti"].(string); jti == "" {
		return nil, uuid.Nil, errors.New("missing jti claim")
	}

	return unverified, clientID, nil
}

// ValidateClientSecretJWT validates a client_secret_jwt assertion (RFC 7523 §2.2).
// hmacKey is the client's per-client HMAC key (already decrypted from
// oauth_clients.secret_hmac_key). The JWT must be signed with HS256.
func ValidateClientSecretJWT(assertion, tokenEndpoint string, hmacKey []byte) (uuid.UUID, error) {
	if len(hmacKey) == 0 {
		return uuid.Nil, errors.New("client has no hmac key configured for client_secret_jwt")
	}
	unverified, clientID, err := validateAssertionCommonClaims(assertion, tokenEndpoint)
	if err != nil {
		return uuid.Nil, err
	}
	if _, ok := unverified.Method.(*jwt.SigningMethodHMAC); !ok {
		return uuid.Nil, errors.New("client_secret_jwt requires an HMAC signing method")
	}
	if _, err := jwt.Parse(assertion, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return hmacKey, nil
	}, jwt.WithExpirationRequired(), jwt.WithValidMethods([]string{"HS256"})); err != nil {
		return uuid.Nil, fmt.Errorf("client assertion verification failed: %w", err)
	}
	return clientID, nil
}

// ValidateClientAssertionJWT validates a private_key_jwt client assertion (RFC 7523).
// It verifies the JWT signature using the client's JWKS, and validates standard claims.
func ValidateClientAssertionJWT(assertion, tokenEndpoint, jwksURI string, jwksCache *JWKSCache) (uuid.UUID, error) {
	unverified, clientID, err := validateAssertionCommonClaims(assertion, tokenEndpoint)
	if err != nil {
		return uuid.Nil, err
	}

	kid, _ := unverified.Header["kid"].(string)
	if kid == "" {
		return uuid.Nil, errors.New("missing kid in JWT header")
	}

	pubKey, err := jwksCache.GetKey(jwksURI, kid)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to get signing key: %w", err)
	}

	if _, err = jwt.Parse(assertion, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			if _, ok := token.Method.(*jwt.SigningMethodRSAPSS); !ok {
				return nil, errors.New("unexpected signing method")
			}
		}
		return pubKey, nil
	}, jwt.WithExpirationRequired()); err != nil {
		return uuid.Nil, fmt.Errorf("client assertion verification failed: %w", err)
	}

	return clientID, nil
}
