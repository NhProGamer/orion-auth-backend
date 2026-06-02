package actiontoken

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func makeClaims() Claims {
	cid := uuid.New()
	rdr := "https://app.example.com/cb"
	return Claims{
		Subject:     uuid.New(),
		Action:      ActionVerifyEmail,
		JTI:         uuid.New().String(),
		ClientID:    &cid,
		RedirectURI: &rdr,
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}
}

func TestSignParse_RoundTrip(t *testing.T) {
	key := makeKey()
	c := makeClaims()

	tok, err := Sign(c, key)
	require.NoError(t, err)
	require.NotEmpty(t, tok)

	got, err := Parse(tok, key)
	require.NoError(t, err)
	assert.Equal(t, c.Subject, got.Subject)
	assert.Equal(t, c.Action, got.Action)
	assert.Equal(t, c.JTI, got.JTI)
	require.NotNil(t, got.ClientID)
	assert.Equal(t, *c.ClientID, *got.ClientID)
	require.NotNil(t, got.RedirectURI)
	assert.Equal(t, *c.RedirectURI, *got.RedirectURI)
}

func TestSignParse_NoOAuthContext(t *testing.T) {
	key := makeKey()
	c := Claims{
		Subject:   uuid.New(),
		Action:    ActionVerifyEmail,
		JTI:       uuid.New().String(),
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	tok, err := Sign(c, key)
	require.NoError(t, err)

	got, err := Parse(tok, key)
	require.NoError(t, err)
	assert.Nil(t, got.ClientID)
	assert.Nil(t, got.RedirectURI)
}

func TestParse_Expired(t *testing.T) {
	key := makeKey()
	c := makeClaims()
	c.IssuedAt = time.Now().Add(-2 * time.Hour)
	c.ExpiresAt = time.Now().Add(-1 * time.Hour)

	tok, err := Sign(c, key)
	require.NoError(t, err)

	_, err = Parse(tok, key)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestParse_WrongKey(t *testing.T) {
	key := makeKey()
	other := make([]byte, 32)
	for i := range other {
		other[i] = 0xff
	}

	tok, err := Sign(makeClaims(), key)
	require.NoError(t, err)

	_, err = Parse(tok, other)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestParse_Tampered(t *testing.T) {
	key := makeKey()
	tok, err := Sign(makeClaims(), key)
	require.NoError(t, err)

	parts := strings.Split(tok, ".")
	require.Len(t, parts, 3)
	// Flip one character in the payload section.
	tampered := parts[0] + "." + parts[1][:len(parts[1])-1] + "A" + "." + parts[2]

	_, err = Parse(tampered, key)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestSign_RequiredFields(t *testing.T) {
	key := makeKey()

	_, err := Sign(Claims{Action: ActionVerifyEmail, JTI: "x", ExpiresAt: time.Now().Add(time.Hour)}, key)
	assert.Error(t, err, "subject required")

	_, err = Sign(Claims{Subject: uuid.New(), JTI: "x", ExpiresAt: time.Now().Add(time.Hour)}, key)
	assert.Error(t, err, "action required")

	_, err = Sign(Claims{Subject: uuid.New(), Action: ActionVerifyEmail, ExpiresAt: time.Now().Add(time.Hour)}, key)
	assert.Error(t, err, "jti required")

	_, err = Sign(Claims{Subject: uuid.New(), Action: ActionVerifyEmail, JTI: "x"}, key)
	assert.Error(t, err, "expires_at required")
}
