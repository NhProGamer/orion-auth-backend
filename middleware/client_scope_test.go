package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/model"
)

func TestContainsScope(t *testing.T) {
	cases := []struct {
		scopes []string
		want   string
		ok     bool
	}{
		{[]string{"m2m:users:read", "m2m:users:write"}, "m2m:users:write", true},
		{[]string{"m2m:users:read"}, "m2m:users:write", false},
		{nil, "m2m:users:read", false},
		{[]string{}, "m2m:users:read", false},
		{[]string{"openid", "profile"}, "openid", true},
	}
	for _, c := range cases {
		if got := containsScope(c.scopes, c.want); got != c.ok {
			t.Errorf("containsScope(%v, %q) = %v, want %v", c.scopes, c.want, got, c.ok)
		}
	}
}

func TestParseBearer(t *testing.T) {
	cases := map[string]string{
		"":                    "",
		"Bearer ":             "",
		"Bearer abc.def":      "abc.def",
		"bearer abc":          "abc",
		"BEARER xyz":          "xyz",
		"Basic abc":           "",
		"Bearer\tabc":         "", // single space required
		"Bearer  doublespace": "", // SplitN(' ', 2) returns " doublespace" with leading space; asserted separately
	}
	delete(cases, "Bearer  doublespace")
	for in, want := range cases {
		if got := ParseBearer(in); got != want {
			t.Errorf("ParseBearer(%q) = %q, want %q", in, got, want)
		}
	}
	if got := ParseBearer("Bearer  doublespace"); got != " doublespace" {
		t.Errorf("ParseBearer with double space: got %q, want %q", got, " doublespace")
	}
}

const m2mAud = "urn:orion:m2m"

func newM2MToken(audience string, userID *uuid.UUID, scopes []string) *model.AccessToken {
	aud := audience
	return tokenWith("hash1", uuid.New(), userID, nil, scopes, &aud)
}

func doScopedGet(mw gin.HandlerFunc, header string) *httptest.ResponseRecorder {
	r := newTestRouter(mw)
	return doGet(r, header)
}

func TestRequireClientScope_MissingHeader(t *testing.T) {
	mw := RequireClientScope(&stubTokens{}, "m2m:users:read", m2mAud)
	w := doScopedGet(mw, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing header: got %d", w.Code)
	}
}

func TestRequireClientScope_TokenNotFound(t *testing.T) {
	mw := RequireClientScope(&stubTokens{byRaw: map[string]*model.AccessToken{}}, "m2m:users:read", m2mAud)
	w := doScopedGet(mw, "Bearer nope")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown token: got %d", w.Code)
	}
}

func TestRequireClientScope_UserBoundTokenRejected(t *testing.T) {
	uid := uuid.New()
	tok := newM2MToken(m2mAud, &uid, []string{"m2m:users:read"})
	mw := RequireClientScope(&stubTokens{byRaw: map[string]*model.AccessToken{"raw1": tok}},
		"m2m:users:read", m2mAud)
	w := doScopedGet(mw, "Bearer raw1")
	if w.Code != http.StatusForbidden {
		t.Fatalf("user-bound token should 403: got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("WWW-Authenticate"), "m2m_only") {
		t.Errorf("missing m2m_only in WWW-Authenticate: %q", w.Header().Get("WWW-Authenticate"))
	}
}

func TestRequireClientScope_WrongAudience(t *testing.T) {
	tok := newM2MToken("urn:other", nil, []string{"m2m:users:read"})
	mw := RequireClientScope(&stubTokens{byRaw: map[string]*model.AccessToken{"raw1": tok}},
		"m2m:users:read", m2mAud)
	w := doScopedGet(mw, "Bearer raw1")
	if w.Code != http.StatusForbidden {
		t.Fatalf("wrong audience should 403: got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("WWW-Authenticate"), "wrong_audience") {
		t.Errorf("missing wrong_audience: %q", w.Header().Get("WWW-Authenticate"))
	}
}

func TestRequireClientScope_InsufficientScope(t *testing.T) {
	tok := newM2MToken(m2mAud, nil, []string{"m2m:users:read"})
	mw := RequireClientScope(&stubTokens{byRaw: map[string]*model.AccessToken{"raw1": tok}},
		"m2m:users:write", m2mAud)
	w := doScopedGet(mw, "Bearer raw1")
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing scope should 403: got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("WWW-Authenticate"), "insufficient_scope") {
		t.Errorf("missing insufficient_scope: %q", w.Header().Get("WWW-Authenticate"))
	}
}

func TestRequireClientScope_NoAudienceOnToken(t *testing.T) {
	tok := tokenWith("hash1", uuid.New(), nil, nil, []string{"m2m:users:read"}, nil)
	mw := RequireClientScope(&stubTokens{byRaw: map[string]*model.AccessToken{"raw1": tok}},
		"m2m:users:read", m2mAud)
	w := doScopedGet(mw, "Bearer raw1")
	if w.Code != http.StatusForbidden {
		t.Fatalf("nil audience should 403: got %d", w.Code)
	}
}

func TestRequireClientScope_Accepted(t *testing.T) {
	cid := uuid.New()
	aud := m2mAud
	tok := &model.AccessToken{
		ID:       "hash1",
		ClientID: cid,
		Audience: &aud,
		Scopes:   []string{"m2m:users:read", "m2m:users:write"},
	}
	mw := RequireClientScope(&stubTokens{byRaw: map[string]*model.AccessToken{"raw1": tok}},
		"m2m:users:write", m2mAud)
	var seenClient uuid.UUID
	r := newTestRouter(mw, func(c *gin.Context) {
		seenClient, _ = GetClientID(c)
	})
	w := doGet(r, "Bearer raw1")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if seenClient != cid {
		t.Errorf("client_id not propagated: got %v want %v", seenClient, cid)
	}
}
