package passkey

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/audit"
	"orion-auth-backend/middleware"
	"orion-auth-backend/pkg"
)

type Handler struct {
	service      *Service
	auditService *audit.Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) SetAuditService(s *audit.Service) {
	h.auditService = s
}

// Wiring:
//   - authenticated: GET/POST/PATCH/DELETE /me/passkeys + reauth begin
//   - public:        POST /me/passkeys/login/{begin,finish} for usernameless login
func (h *Handler) RegisterRoutes(
	public *gin.RouterGroup,
	authenticated *gin.RouterGroup,
	readPerm gin.HandlerFunc,
	managePerm gin.HandlerFunc,
	requireReauth gin.HandlerFunc,
) {
	if public != nil {
		public.POST("/me/passkeys/login/begin", h.LoginBegin)
		public.POST("/me/passkeys/login/finish", h.LoginFinish)
	}

	if authenticated != nil {
		read := authenticated.Group("")
		if readPerm != nil {
			read.Use(readPerm)
		}
		read.GET("/me/passkeys", h.List)

		manage := authenticated.Group("")
		if managePerm != nil {
			manage.Use(managePerm)
		}
		manage.POST("/me/passkeys/register/begin", h.RegisterBegin)
		manage.POST("/me/passkeys/register/finish", h.RegisterFinish)
		manage.PATCH("/me/passkeys/:id", h.Rename)
		manage.POST("/me/passkeys/reauth/begin", h.ReauthBegin)

		sensitive := manage.Group("")
		if requireReauth != nil {
			sensitive.Use(requireReauth)
		}
		sensitive.DELETE("/me/passkeys/:id", h.Delete)
	}
}

// RegisterBegin godoc
// @Summary Start passkey registration
// @Tags    Account
// @Produce json
// @Success 200 {object} map[string]any "challenge_id (uuid) + options (PublicKeyCredentialCreationOptions JSON)"
// @Security BearerAuth
// @Router  /api/v1/me/passkeys/register/begin [post]
func (h *Handler) RegisterBegin(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}
	resp, err := h.service.BeginRegistration(userID)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	pkg.OK(c, resp)
}

// RegisterFinish godoc
// @Summary  Finish passkey registration
// @Tags     Account
// @Accept   json
// @Produce  json
// @Param    body body passkey.FinishRegistrationInput true "challenge id + raw response"
// @Success  200 {object} map[string]any
// @Security BearerAuth
// @Router   /api/v1/me/passkeys/register/finish [post]
func (h *Handler) RegisterFinish(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}
	var input FinishRegistrationInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	p, err := h.service.FinishRegistration(userID, input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionAccountPasskeyAdded, map[string]any{
			"passkey_id": p.ID,
			"name":       p.Name,
		})
	}
	pkg.OK(c, gin.H{"passkey": p.PublicView()})
}

// List godoc
// @Summary  List own passkeys
// @Tags     Account
// @Produce  json
// @Success  200 {object} map[string]any
// @Security BearerAuth
// @Router   /api/v1/me/passkeys [get]
func (h *Handler) List(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}
	pks, err := h.service.List(userID)
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to list passkeys"))
		return
	}
	out := make([]map[string]any, len(pks))
	for i := range pks {
		out[i] = pks[i].PublicView()
	}
	pkg.OK(c, gin.H{"passkeys": out})
}

// Rename godoc
// @Summary  Rename a passkey
// @Tags     Account
// @Accept   json
// @Produce  json
// @Param    id path string true "Passkey ID"
// @Param    body body passkey.RenameInput true "new name"
// @Success  200 {object} map[string]any
// @Security BearerAuth
// @Router   /api/v1/me/passkeys/{id} [patch]
func (h *Handler) Rename(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid passkey id"))
		return
	}
	var input RenameInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	if err := h.service.Rename(id, userID, input.Name); err != nil {
		pkg.HandleError(c, err)
		return
	}
	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionAccountPasskeyRenamed, map[string]any{
			"passkey_id": id,
			"name":       input.Name,
		})
	}
	pkg.OK(c, gin.H{"message": "passkey renamed"})
}

// Delete godoc
// @Summary  Delete a passkey (step-up required)
// @Tags     Account
// @Produce  json
// @Param    id path string true "Passkey ID"
// @Success  200 {object} map[string]any
// @Security BearerAuth
// @Router   /api/v1/me/passkeys/{id} [delete]
func (h *Handler) Delete(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid passkey id"))
		return
	}
	if err := h.service.Delete(id, userID); err != nil {
		pkg.HandleError(c, err)
		return
	}
	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionAccountPasskeyRemoved, map[string]any{
			"passkey_id": id,
		})
	}
	pkg.OK(c, gin.H{"message": "passkey removed"})
}

// ReauthBegin godoc
// @Summary  Start a passkey-based reauth challenge
// @Tags     Account
// @Produce  json
// @Success  200 {object} map[string]any "challenge_id (uuid) + options (PublicKeyCredentialRequestOptions JSON)"
// @Security BearerAuth
// @Router   /api/v1/me/passkeys/reauth/begin [post]
func (h *Handler) ReauthBegin(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		pkg.HandleError(c, pkg.ErrUnauthorized("not authenticated"))
		return
	}
	resp, err := h.service.BeginReauth(userID)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	pkg.OK(c, resp)
}

// LoginBegin godoc
// @Summary  Begin usernameless passkey login (public)
// @Tags     Account
// @Produce  json
// @Success  200 {object} map[string]any "challenge_id (uuid) + options (PublicKeyCredentialRequestOptions JSON)"
// @Router   /api/v1/me/passkeys/login/begin [post]
func (h *Handler) LoginBegin(c *gin.Context) {
	resp, err := h.service.BeginLogin()
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	pkg.OK(c, resp)
}

// LoginFinish godoc
// @Summary  Finish usernameless passkey login (public). Returns the user and passkey; caller is responsible for issuing a session.
// @Tags     Account
// @Accept   json
// @Produce  json
// @Param    body body passkey.FinishLoginInput true "challenge id + raw response"
// @Success  200 {object} map[string]any
// @Router   /api/v1/me/passkeys/login/finish [post]
func (h *Handler) LoginFinish(c *gin.Context) {
	var input FinishLoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	u, p, err := h.service.FinishLogin(input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	out := gin.H{
		"user_id": u.ID,
		"email":   u.Email,
	}
	if p != nil {
		out["passkey_id"] = p.ID
	}
	pkg.OK(c, out)
}
