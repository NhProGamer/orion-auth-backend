package oidc

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// SupportedJWEAlgs is the list of key-management algorithms this server
// advertises in discovery for ID token / UserInfo encryption.
var SupportedJWEAlgs = []string{
	"RSA-OAEP-256",
	"RSA-OAEP",
	"ECDH-ES",
	"ECDH-ES+A128KW",
	"ECDH-ES+A256KW",
}

// SupportedJWEEncs is the list of content-encryption algorithms.
var SupportedJWEEncs = []string{
	"A256GCM",
	"A128GCM",
	"A256CBC-HS512",
	"A128CBC-HS256",
}

func lookupKeyAlg(name string) (jwa.KeyEncryptionAlgorithm, bool) {
	return jwa.LookupKeyEncryptionAlgorithm(name)
}

func lookupContentAlg(name string) (jwa.ContentEncryptionAlgorithm, bool) {
	return jwa.LookupContentEncryptionAlgorithm(name)
}

// ValidateJWEEncryptionPair validates that the alg/enc pair is supported.
// Used by DCR to reject configurations the server can't honour.
func ValidateJWEEncryptionPair(alg, enc string) error {
	if alg == "" && enc == "" {
		return nil
	}
	if alg == "" || enc == "" {
		return errors.New("both alg and enc must be set together")
	}
	if _, ok := lookupKeyAlg(alg); !ok {
		return fmt.Errorf("unsupported encryption alg: %s", alg)
	}
	if _, ok := lookupContentAlg(enc); !ok {
		return fmt.Errorf("unsupported encryption enc: %s", enc)
	}
	return nil
}

// jweJWKSCache caches client JWKS documents fetched for the purpose of
// selecting an encryption key. Separate from the middleware JWKS cache so
// we can hold parsed jwk.Set objects (which the middleware doesn't need).
type jweJWKSCache struct {
	mu      sync.RWMutex
	entries map[string]jweJWKSCacheEntry
}

type jweJWKSCacheEntry struct {
	set       jwk.Set
	fetchedAt time.Time
}

const jweJWKSCacheTTL = 5 * time.Minute

var defaultJWEJWKSCache = &jweJWKSCache{entries: map[string]jweJWKSCacheEntry{}}

func (c *jweJWKSCache) get(uri string) (jwk.Set, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[uri]
	if !ok || time.Since(e.fetchedAt) > jweJWKSCacheTTL {
		return nil, false
	}
	return e.set, true
}

func (c *jweJWKSCache) set(uri string, set jwk.Set) {
	c.mu.Lock()
	c.entries[uri] = jweJWKSCacheEntry{set: set, fetchedAt: time.Now()}
	c.mu.Unlock()
}

func fetchClientJWKS(jwksURI string) (jwk.Set, error) {
	if set, ok := defaultJWEJWKSCache.get(jwksURI); ok {
		return set, nil
	}
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpClient.Get(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("fetch client jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client jwks endpoint returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read client jwks body: %w", err)
	}
	set, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("parse client jwks: %w", err)
	}
	defaultJWEJWKSCache.set(jwksURI, set)
	return set, nil
}

// pickEncryptionKey scans the JWK Set for a key suitable for encryption.
// Preference order:
//   1. keys explicitly marked use=enc
//   2. keys without a use claim (RFC 7517 §4.2 leaves this acceptable)
//
// Keys marked use=sig are skipped entirely. Returns nil if no candidate exists.
func pickEncryptionKey(set jwk.Set) (jwk.Key, error) {
	var fallback jwk.Key
	for i := 0; i < set.Len(); i++ {
		k, ok := set.Key(i)
		if !ok {
			continue
		}
		var use string
		if err := k.Get(jwk.KeyUsageKey, &use); err != nil {
			use = ""
		}
		switch use {
		case "enc":
			return k, nil
		case "":
			if fallback == nil {
				fallback = k
			}
		}
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, errors.New("no encryption-capable key found in client JWKS")
}

// EncryptForClient seals the given payload (typically a signed JWS) as a
// compact-serialized JWE using the client's JWKS public key. Both alg and
// enc must be set and supported. Returns the JWE compact serialization
// suitable for placing in a token response (id_token or userinfo body).
func (s *Service) EncryptForClient(payload []byte, jwksURI, alg, enc string) (string, error) {
	keyAlg, ok := lookupKeyAlg(alg)
	if !ok {
		return "", fmt.Errorf("unsupported encryption alg: %s", alg)
	}
	contentAlg, ok := lookupContentAlg(enc)
	if !ok {
		return "", fmt.Errorf("unsupported encryption enc: %s", enc)
	}
	if jwksURI == "" {
		return "", errors.New("client has no jwks_uri configured; cannot encrypt")
	}

	set, err := fetchClientJWKS(jwksURI)
	if err != nil {
		return "", err
	}
	key, err := pickEncryptionKey(set)
	if err != nil {
		return "", err
	}

	hdrs := jwe.NewHeaders()
	var kid string
	if err := key.Get(jwk.KeyIDKey, &kid); err == nil && kid != "" {
		_ = hdrs.Set("kid", kid)
	}

	encrypted, err := jwe.Encrypt(payload,
		jwe.WithKey(keyAlg, key),
		jwe.WithContentEncryption(contentAlg),
		jwe.WithProtectedHeaders(hdrs),
	)
	if err != nil {
		return "", fmt.Errorf("jwe encrypt: %w", err)
	}
	return string(encrypted), nil
}

// resetJWEJWKSCacheForTest is exposed for tests that spin up a mock JWKS
// server and want a clean slate. Not part of the public API.
func resetJWEJWKSCacheForTest() {
	defaultJWEJWKSCache.mu.Lock()
	defaultJWEJWKSCache.entries = map[string]jweJWKSCacheEntry{}
	defaultJWEJWKSCache.mu.Unlock()
}
