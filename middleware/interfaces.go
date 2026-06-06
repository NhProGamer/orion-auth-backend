package middleware

import (
	"github.com/google/uuid"

	"orion-auth-backend/model"
)

// ClientFinder loads an active OAuth client by ID. Implementations MUST
// enforce active = true so the middleware does not have to guess whether
// the client is enabled. Used by ClientAuth for both the credential-bound
// lookup and the JWT client_assertion sub-claim resolution.
type ClientFinder interface {
	FindActive(id uuid.UUID) (*model.OAuthClient, error)
}

// TokenLookup hashes the raw bearer token and returns the matching access
// token row, but only when it is non-revoked and non-expired. The raw form
// (not the hash) is passed in because hashing is a token-format detail the
// caller (middleware) should not have to know.
type TokenLookup interface {
	LookupActiveAccessToken(raw string) (*model.AccessToken, error)
}

// SessionValidator answers "is this session still good to authorize
// requests?". Used by BearerAuth to gate user-bound access tokens behind
// the parent session: revoking the session must revoke every token it
// vouches for, even ones whose own expires_at hasn't elapsed yet.
type SessionValidator interface {
	IsActive(id uuid.UUID) (bool, error)
}
