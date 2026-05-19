package oauth

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"orion-auth-backend/middleware"
	"orion-auth-backend/model"
)

// requestObjectFetchTimeout caps the time spent fetching a remote Request
// Object (RFC 9101 §5.2.2). Kept short to avoid stalling /authorize.
const requestObjectFetchTimeout = 5 * time.Second

// requestObjectMaxBytes is the upper bound on the JWT body we accept from a
// remote request_uri. JWT Request Objects are kilobytes at worst; anything
// larger is likely an attempt to exhaust memory.
const requestObjectMaxBytes = 1 << 20 // 1 MiB

// requestObjectFetchCacheTTL is how long a successful fetch is cached for.
// Clients that mutate Request Objects must rotate URLs (or wait).
const requestObjectFetchCacheTTL = 5 * time.Minute

// ParseAndVerifyRequestObject parses a JAR Request Object (RFC 9101) and
// REQUIRES that its signature can be verified against the client's JWKS.
// alg=none is rejected unconditionally — accepting unsigned request objects
// would let any caller override authorize parameters (e.g. scope, audience,
// redirect_uri) on behalf of the client.
//
// The returned map mirrors the JWT claims that should be lifted into
// InitAuthorizeParams via mergeJARParams. Non-string claim values are
// dropped to match the existing handler contract.
func ParseAndVerifyRequestObject(jwtStr string, client *model.OAuthClient, jwksCache *middleware.JWKSCache) (map[string]string, error) {
	if client == nil {
		return nil, errors.New("nil client")
	}
	if client.JWKSUri == nil || *client.JWKSUri == "" {
		return nil, errors.New("client has no jwks_uri configured; signed request objects are required")
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	unverified, _, err := parser.ParseUnverified(jwtStr, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("malformed request object: %w", err)
	}

	alg, _ := unverified.Header["alg"].(string)
	if alg == "" || alg == "none" {
		return nil, errors.New("request object must be signed (alg=none rejected)")
	}

	kid, _ := unverified.Header["kid"].(string)
	if kid == "" {
		return nil, errors.New("missing kid in request object header")
	}

	pubKey, err := jwksCache.GetKey(*client.JWKSUri, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve request object signing key: %w", err)
	}

	verified, err := jwt.Parse(jwtStr, func(token *jwt.Token) (any, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS, *jwt.SigningMethodECDSA:
			return pubKey, nil
		default:
			return nil, fmt.Errorf("unsupported request object alg %q", alg)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("request object signature verification failed: %w", err)
	}

	claims, ok := verified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid request object claims")
	}

	out := make(map[string]string, len(claims))
	for k, v := range claims {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out, nil
}

// requestObjectFetchCache is an in-process cache of fetched Request Objects
// keyed by URL. Avoids hammering the RP's server when /authorize is hit in a
// burst (e.g. browser retry). Successful fetches are cached for
// requestObjectFetchCacheTTL; failures are not cached so we recover quickly.
type requestObjectFetchCache struct {
	mu      sync.RWMutex
	entries map[string]requestObjectFetchEntry
}

type requestObjectFetchEntry struct {
	body      string
	fetchedAt time.Time
}

var defaultRequestObjectCache = &requestObjectFetchCache{entries: map[string]requestObjectFetchEntry{}}

func (c *requestObjectFetchCache) get(url string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[url]
	if !ok {
		return "", false
	}
	if time.Since(e.fetchedAt) > requestObjectFetchCacheTTL {
		return "", false
	}
	return e.body, true
}

func (c *requestObjectFetchCache) set(url, body string) {
	c.mu.Lock()
	c.entries[url] = requestObjectFetchEntry{body: body, fetchedAt: time.Now()}
	c.mu.Unlock()
}

// FetchRequestURI GETs a JWT Request Object from a remote HTTPS URL. Caller
// is responsible for whitelisting the URL via client.HasRequestURI BEFORE
// calling this — we do not enforce that here.
func FetchRequestURI(url string) (string, error) {
	if body, ok := defaultRequestObjectCache.get(url); ok {
		return body, nil
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/oauth-authz-req+jwt")

	httpClient := &http.Client{Timeout: requestObjectFetchTimeout}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch request_uri: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request_uri returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, requestObjectMaxBytes+1))
	if err != nil {
		return "", fmt.Errorf("read request_uri body: %w", err)
	}
	if len(body) > requestObjectMaxBytes {
		return "", fmt.Errorf("request_uri body exceeds %d bytes", requestObjectMaxBytes)
	}

	out := string(body)
	defaultRequestObjectCache.set(url, out)
	return out, nil
}
