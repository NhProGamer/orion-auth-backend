package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/model"
)

func newTestRouter(handlers ...gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	chain := append(handlers, func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	r.GET("/probe", chain...)
	return r
}

func doGet(r *gin.Engine, authHeader string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	r.ServeHTTP(w, req)
	return w
}

func TestBearerAuth_MissingHeader(t *testing.T) {
	mw := BearerAuth(&stubTokens{}, &stubSessions{})
	r := newTestRouter(mw)
	w := doGet(r, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing header: got %d, want 401", w.Code)
	}
}

func TestBearerAuth_TokenNotFound(t *testing.T) {
	mw := BearerAuth(&stubTokens{byRaw: map[string]*model.AccessToken{}}, &stubSessions{})
	r := newTestRouter(mw)
	w := doGet(r, "Bearer unknown")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown token: got %d, want 401", w.Code)
	}
}

func TestBearerAuth_TokenLookupError(t *testing.T) {
	mw := BearerAuth(&stubTokens{err: errBoom}, &stubSessions{})
	r := newTestRouter(mw)
	w := doGet(r, "Bearer anything")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("token lookup error: got %d, want 401", w.Code)
	}
}

func TestBearerAuth_ClientCredentialsTokenAccepted(t *testing.T) {
	cid := uuid.New()
	tokens := &stubTokens{byRaw: map[string]*model.AccessToken{
		"raw1": tokenWith("hash1", cid, nil, nil, []string{"openid"}, nil),
	}}
	var seenClientID uuid.UUID
	var seenScopes []string
	mw := BearerAuth(tokens, &stubSessions{})
	r := newTestRouter(mw, func(c *gin.Context) {
		seenClientID, _ = GetClientID(c)
		seenScopes = GetScopes(c)
	})
	w := doGet(r, "Bearer raw1")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if seenClientID != cid {
		t.Errorf("client id not propagated: got %v want %v", seenClientID, cid)
	}
	if len(seenScopes) != 1 || seenScopes[0] != "openid" {
		t.Errorf("scopes not propagated: %v", seenScopes)
	}
}

func TestBearerAuth_UserBoundTokenWithRevokedSession(t *testing.T) {
	uid := uuid.New()
	sid := uuid.New()
	tokens := &stubTokens{byRaw: map[string]*model.AccessToken{
		"raw1": tokenWith("hash1", uuid.New(), &uid, &sid, []string{"openid"}, nil),
	}}
	sessions := &stubSessions{active: map[uuid.UUID]bool{sid: false}}
	mw := BearerAuth(tokens, sessions)
	r := newTestRouter(mw)
	w := doGet(r, "Bearer raw1")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session should 401: got %d", w.Code)
	}
}

func TestBearerAuth_UserBoundTokenWithActiveSession(t *testing.T) {
	uid := uuid.New()
	sid := uuid.New()
	cid := uuid.New()
	tokens := &stubTokens{byRaw: map[string]*model.AccessToken{
		"raw1": tokenWith("hash1", cid, &uid, &sid, []string{"openid", "profile"}, nil),
	}}
	sessions := &stubSessions{active: map[uuid.UUID]bool{sid: true}}
	var seenUser, seenSession uuid.UUID
	mw := BearerAuth(tokens, sessions)
	r := newTestRouter(mw, func(c *gin.Context) {
		seenUser, _ = GetUserID(c)
		seenSession, _ = GetSessionID(c)
	})
	w := doGet(r, "Bearer raw1")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if seenUser != uid {
		t.Errorf("user id not propagated: got %v want %v", seenUser, uid)
	}
	if seenSession != sid {
		t.Errorf("session id not propagated: got %v want %v", seenSession, sid)
	}
}

func TestBearerAuth_SessionValidatorError(t *testing.T) {
	uid := uuid.New()
	sid := uuid.New()
	tokens := &stubTokens{byRaw: map[string]*model.AccessToken{
		"raw1": tokenWith("hash1", uuid.New(), &uid, &sid, []string{"openid"}, nil),
	}}
	sessions := &stubSessions{err: errBoom}
	mw := BearerAuth(tokens, sessions)
	r := newTestRouter(mw)
	w := doGet(r, "Bearer raw1")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("session validator error must reject: got %d", w.Code)
	}
}
