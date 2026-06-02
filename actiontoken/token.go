// Package actiontoken issues and validates short-lived HS256 JWTs used by
// out-of-band actions (e.g. verify-email). The token carries the optional
// OAuth context (client_id, redirect_uri) needed to bootstrap a session and
// continue the authorize flow after the user clicks the email link.
package actiontoken

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Action constants identify the intent encoded in the token. The verify
// endpoint must check both the signature AND the action.
const (
	ActionVerifyEmail = "verify_email"
)

// Claims captures what the action token holds. ClientID and RedirectURI are
// optional: when both are set, the consumer is expected to bootstrap a
// session and redirect to the OAuth client; otherwise it falls back to a
// generic success screen.
type Claims struct {
	Subject     uuid.UUID
	Action      string
	JTI         string
	ClientID    *uuid.UUID
	RedirectURI *string
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// jwtClaims is the wire shape used by golang-jwt/jwt — pointer fields keep
// optional OAuth context out of the encoded payload when absent.
type jwtClaims struct {
	jwt.RegisteredClaims
	Action      string  `json:"act"`
	ClientID    *string `json:"cid,omitempty"`
	RedirectURI *string `json:"rdr,omitempty"`
}

// Sign returns an HS256 JWT carrying the supplied claims. The key must be at
// least 32 bytes (caller's responsibility).
func Sign(c Claims, key []byte) (string, error) {
	if c.Subject == uuid.Nil {
		return "", errors.New("actiontoken: subject is required")
	}
	if c.Action == "" {
		return "", errors.New("actiontoken: action is required")
	}
	if c.JTI == "" {
		return "", errors.New("actiontoken: jti is required")
	}
	if c.ExpiresAt.IsZero() {
		return "", errors.New("actiontoken: expires_at is required")
	}

	jc := jwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   c.Subject.String(),
			ID:        c.JTI,
			IssuedAt:  jwt.NewNumericDate(c.IssuedAt),
			ExpiresAt: jwt.NewNumericDate(c.ExpiresAt),
		},
		Action: c.Action,
	}
	if c.ClientID != nil {
		s := c.ClientID.String()
		jc.ClientID = &s
	}
	if c.RedirectURI != nil {
		jc.RedirectURI = c.RedirectURI
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jc)
	return tok.SignedString(key)
}

// Parse validates the signature, expiration and required claims, and returns
// the decoded Claims. Tampering, expired, or wrong-algorithm tokens all
// surface as a single ErrInvalidToken so callers can return a uniform error
// without leaking why the token was rejected.
var ErrInvalidToken = errors.New("actiontoken: invalid or expired token")

func Parse(raw string, key []byte) (*Claims, error) {
	var jc jwtClaims
	_, err := jwt.ParseWithClaims(raw, &jc, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
	if err != nil {
		return nil, ErrInvalidToken
	}

	subj, err := uuid.Parse(jc.Subject)
	if err != nil {
		return nil, ErrInvalidToken
	}
	if jc.Action == "" || jc.ID == "" {
		return nil, ErrInvalidToken
	}

	out := &Claims{
		Subject:   subj,
		Action:    jc.Action,
		JTI:       jc.ID,
		IssuedAt:  jc.IssuedAt.Time,
		ExpiresAt: jc.ExpiresAt.Time,
	}
	if jc.ClientID != nil {
		cid, err := uuid.Parse(*jc.ClientID)
		if err != nil {
			return nil, ErrInvalidToken
		}
		out.ClientID = &cid
	}
	out.RedirectURI = jc.RedirectURI

	return out, nil
}
