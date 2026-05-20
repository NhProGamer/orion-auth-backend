package oauth

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildAuthorizeRedirectURL_QueryDefault(t *testing.T) {
	got, err := BuildAuthorizeRedirectURL(&AuthorizeConsentResponse{
		RedirectURI: "https://client.example.com/cb",
		Code:        "abc123",
		State:       "s",
		Issuer:      "https://auth.example.com",
	})
	require.NoError(t, err)

	u, err := url.Parse(got)
	require.NoError(t, err)
	q := u.Query()
	assert.Equal(t, "abc123", q.Get("code"))
	assert.Equal(t, "s", q.Get("state"))
	assert.Equal(t, "https://auth.example.com", q.Get("iss"))
	assert.Empty(t, u.Fragment, "default response_mode must put params in the query string")
}

func TestBuildAuthorizeRedirectURL_FragmentResponseMode(t *testing.T) {
	got, err := BuildAuthorizeRedirectURL(&AuthorizeConsentResponse{
		RedirectURI:  "https://client.example.com/cb",
		Code:         "abc123",
		State:        "s",
		ResponseMode: "fragment",
	})
	require.NoError(t, err)
	assert.True(t, strings.Contains(got, "#code=abc123"), "fragment mode must use # delimiter")
	assert.False(t, strings.Contains(got, "?code="), "fragment mode must not put params in query")
}

func TestBuildAuthorizeRedirectURL_PreservesExistingQueryParams(t *testing.T) {
	got, err := BuildAuthorizeRedirectURL(&AuthorizeConsentResponse{
		RedirectURI: "https://client.example.com/cb?source=login",
		Code:        "abc",
	})
	require.NoError(t, err)
	u, _ := url.Parse(got)
	q := u.Query()
	assert.Equal(t, "login", q.Get("source"))
	assert.Equal(t, "abc", q.Get("code"))
}

func TestBuildAuthorizeRedirectURL_RejectsEmpty(t *testing.T) {
	_, err := BuildAuthorizeRedirectURL(nil)
	require.Error(t, err)
	_, err = BuildAuthorizeRedirectURL(&AuthorizeConsentResponse{})
	require.Error(t, err)
}
