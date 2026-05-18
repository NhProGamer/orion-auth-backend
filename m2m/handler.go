package m2m

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/audit"
	"orion-auth-backend/middleware"
	"orion-auth-backend/pkg"
)

type Handler struct {
	service      *UserService
	auditService *audit.Service
}

func NewHandler(service *UserService) *Handler {
	return &Handler{service: service}
}

func (h *Handler) SetAuditService(s *audit.Service) {
	h.auditService = s
}

// RegisterRoutes wires the M2M user endpoints under their respective scope
// groups. Each `*Group` is expected to already carry the
// `middleware.RequireClientScope(db, "m2m:users:<scope>", "urn:orion:m2m")`
// middleware applied by main.go.
func (h *Handler) RegisterRoutes(read, write, deleteGrp, manageAuth, manageRoles *gin.RouterGroup) {
	// Read
	read.GET("/users", h.List)
	read.GET("/users/:id", h.Get)
	read.GET("/users/:id/roles", h.ListRoles)
	read.GET("/users/:id/sessions", h.ListSessions)
	read.GET("/users/:id/passkeys", h.ListPasskeys)
	read.GET("/users/:id/linked-accounts", h.ListLinkedAccounts)

	// Write (create + update)
	write.POST("/users", h.Create)
	write.PATCH("/users/:id", h.Update)

	// Delete
	deleteGrp.DELETE("/users/:id", h.Delete)

	// Manage auth (password, unlock, MFA reset, revoke sessions/passkeys/links)
	manageAuth.PUT("/users/:id/password", h.SetPassword)
	manageAuth.POST("/users/:id/unlock", h.Unlock)
	manageAuth.POST("/users/:id/mfa/reset", h.ResetMFA)
	manageAuth.DELETE("/users/:id/sessions/:sid", h.RevokeSession)
	manageAuth.DELETE("/users/:id/sessions", h.RevokeAllSessions)
	manageAuth.DELETE("/users/:id/passkeys/:pid", h.DeletePasskey)
	manageAuth.DELETE("/users/:id/linked-accounts/:linkId", h.UnlinkAccount)

	// Manage roles
	manageRoles.POST("/users/:id/roles", h.AssignRole)
	manageRoles.DELETE("/users/:id/roles/:roleId", h.RemoveRole)
}

// audit logs the action with caller client_id (from the M2M token) and the
// affected user in metadata.target_user_id. Caller can pass extra metadata.
func (h *Handler) audit(c *gin.Context, action string, targetUserID uuid.UUID, extra map[string]any) {
	if h.auditService == nil {
		return
	}
	meta := map[string]any{"target_user_id": targetUserID}
	for k, v := range extra {
		meta[k] = v
	}
	cid, _ := middleware.GetClientID(c)
	entry := audit.LogEntry{
		Action:    action,
		ClientID:  &cid,
		IPAddress: c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
		Metadata:  meta,
	}
	h.auditService.Log(entry)
}

// --- helpers ---

func parseUserID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid user id"))
		return uuid.Nil, false
	}
	return id, true
}

func parseParamUUID(c *gin.Context, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param(name))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid "+name))
		return uuid.Nil, false
	}
	return id, true
}

// --- CRUD ---

// List godoc
// @Summary List users (paginated)
// @Tags    M2M - Users
// @Produce json
// @Param   page query int false "Page (default 1)"
// @Param   per_page query int false "Per page (default 20, max 100)"
// @Success 200 {object} pkg.PaginatedResponse
// @Router  /api/v1/m2m/users [get]
func (h *Handler) List(c *gin.Context) {
	page, perPage := pkg.ParsePagination(c)
	users, total, err := h.service.List(page, perPage)
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to list users"))
		return
	}
	views := make([]map[string]any, len(users))
	for i := range users {
		views[i] = users[i].AdminView()
	}
	pkg.Paginated(c, views, total, page, perPage)
}

// Get godoc
// @Summary Get a user by id
// @Tags    M2M - Users
// @Produce json
// @Param   id path string true "User id"
// @Success 200 {object} map[string]any
// @Router  /api/v1/m2m/users/{id} [get]
func (h *Handler) Get(c *gin.Context) {
	id, ok := parseUserID(c)
	if !ok {
		return
	}
	u, err := h.service.Get(id)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	pkg.OK(c, gin.H{"user": u.AdminView()})
}

// Create godoc
// @Summary Create a user
// @Tags    M2M - Users
// @Accept  json
// @Produce json
// @Param   body body m2m.CreateUserInput true "User to create"
// @Success 201 {object} m2m.CreateUserResult
// @Router  /api/v1/m2m/users [post]
func (h *Handler) Create(c *gin.Context) {
	var input CreateUserInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	u, generated, err := h.service.Create(input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	h.audit(c, audit.ActionM2MUserCreated, u.ID, map[string]any{
		"email":    u.Email,
		"role_ids": input.RoleIDs,
	})
	result := CreateUserResult{User: u.AdminView()}
	if generated != "" {
		result.GeneratedPassword = generated
	}
	pkg.Created(c, result)
}

// Update godoc
// @Summary Update a user (any field except id)
// @Tags    M2M - Users
// @Accept  json
// @Produce json
// @Param   id path string true "User id"
// @Param   body body m2m.UpdateUserInput true "Fields to update"
// @Success 200 {object} map[string]any
// @Router  /api/v1/m2m/users/{id} [patch]
func (h *Handler) Update(c *gin.Context) {
	id, ok := parseUserID(c)
	if !ok {
		return
	}
	var input UpdateUserInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	u, err := h.service.Update(id, input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	h.audit(c, audit.ActionM2MUserUpdated, id, nil)
	pkg.OK(c, gin.H{"user": u.AdminView()})
}

// Delete godoc
// @Summary Delete a user
// @Tags    M2M - Users
// @Param   id path string true "User id"
// @Success 200 {object} map[string]any
// @Router  /api/v1/m2m/users/{id} [delete]
func (h *Handler) Delete(c *gin.Context) {
	id, ok := parseUserID(c)
	if !ok {
		return
	}
	if err := h.service.Delete(id); err != nil {
		pkg.HandleError(c, err)
		return
	}
	h.audit(c, audit.ActionM2MUserDeleted, id, nil)
	pkg.OK(c, gin.H{"message": "user deleted"})
}

// --- Credentials ---

// SetPassword godoc
// @Summary Set a user's password (no current-password check)
// @Tags    M2M - Users
// @Accept  json
// @Produce json
// @Param   id path string true "User id"
// @Param   body body m2m.SetPasswordInput true "New password"
// @Success 200 {object} map[string]any
// @Router  /api/v1/m2m/users/{id}/password [put]
func (h *Handler) SetPassword(c *gin.Context) {
	id, ok := parseUserID(c)
	if !ok {
		return
	}
	var input SetPasswordInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	if err := h.service.SetPassword(id, input.Password); err != nil {
		pkg.HandleError(c, err)
		return
	}
	h.audit(c, audit.ActionM2MUserPasswordSet, id, nil)
	pkg.OK(c, gin.H{"message": "password set; all sessions revoked"})
}

// Unlock godoc
// @Summary Clear lock-out (failed_login_attempts + locked_until)
// @Tags    M2M - Users
// @Param   id path string true "User id"
// @Success 200 {object} map[string]any
// @Router  /api/v1/m2m/users/{id}/unlock [post]
func (h *Handler) Unlock(c *gin.Context) {
	id, ok := parseUserID(c)
	if !ok {
		return
	}
	if err := h.service.Unlock(id); err != nil {
		pkg.HandleError(c, err)
		return
	}
	h.audit(c, audit.ActionM2MUserUnlocked, id, nil)
	pkg.OK(c, gin.H{"message": "account unlocked"})
}

// ResetMFA godoc
// @Summary Force-disable TOTP MFA for a user
// @Tags    M2M - Users
// @Param   id path string true "User id"
// @Success 200 {object} map[string]any
// @Router  /api/v1/m2m/users/{id}/mfa/reset [post]
func (h *Handler) ResetMFA(c *gin.Context) {
	id, ok := parseUserID(c)
	if !ok {
		return
	}
	if err := h.service.ResetMFA(id); err != nil {
		pkg.HandleError(c, err)
		return
	}
	h.audit(c, audit.ActionM2MUserMFAReset, id, nil)
	pkg.OK(c, gin.H{"message": "MFA reset"})
}

// --- Roles ---

func (h *Handler) ListRoles(c *gin.Context) {
	id, ok := parseUserID(c)
	if !ok {
		return
	}
	roles, err := h.service.ListRoles(id)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	pkg.OK(c, gin.H{"roles": roles})
}

func (h *Handler) AssignRole(c *gin.Context) {
	id, ok := parseUserID(c)
	if !ok {
		return
	}
	var input AssignRoleInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	if err := h.service.AssignRole(id, input.RoleID); err != nil {
		pkg.HandleError(c, err)
		return
	}
	h.audit(c, audit.ActionM2MUserRoleAssigned, id, map[string]any{"role_id": input.RoleID})
	pkg.OK(c, gin.H{"message": "role assigned"})
}

func (h *Handler) RemoveRole(c *gin.Context) {
	id, ok := parseUserID(c)
	if !ok {
		return
	}
	roleID, ok := parseParamUUID(c, "roleId")
	if !ok {
		return
	}
	if err := h.service.RemoveRole(id, roleID); err != nil {
		pkg.HandleError(c, err)
		return
	}
	h.audit(c, audit.ActionM2MUserRoleRemoved, id, map[string]any{"role_id": roleID})
	pkg.OK(c, gin.H{"message": "role removed"})
}

// --- Sessions ---

func (h *Handler) ListSessions(c *gin.Context) {
	id, ok := parseUserID(c)
	if !ok {
		return
	}
	sessions, err := h.service.ListSessions(id)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	pkg.OK(c, gin.H{"sessions": sessions})
}

func (h *Handler) RevokeSession(c *gin.Context) {
	id, ok := parseUserID(c)
	if !ok {
		return
	}
	sid, ok := parseParamUUID(c, "sid")
	if !ok {
		return
	}
	if err := h.service.RevokeSession(sid, id); err != nil {
		pkg.HandleError(c, err)
		return
	}
	h.audit(c, audit.ActionM2MUserSessionRevoked, id, map[string]any{"session_id": sid})
	pkg.OK(c, gin.H{"message": "session revoked"})
}

func (h *Handler) RevokeAllSessions(c *gin.Context) {
	id, ok := parseUserID(c)
	if !ok {
		return
	}
	count, err := h.service.RevokeAllSessions(id)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	h.audit(c, audit.ActionM2MUserSessionRevoked, id, map[string]any{"revoked_count": count, "all": true})
	pkg.OK(c, gin.H{"message": "all sessions revoked", "revoked_count": count})
}

// --- Passkeys ---

func (h *Handler) ListPasskeys(c *gin.Context) {
	id, ok := parseUserID(c)
	if !ok {
		return
	}
	pks, err := h.service.ListPasskeys(id)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	views := make([]map[string]any, len(pks))
	for i := range pks {
		views[i] = pks[i].PublicView()
	}
	pkg.OK(c, gin.H{"passkeys": views})
}

func (h *Handler) DeletePasskey(c *gin.Context) {
	id, ok := parseUserID(c)
	if !ok {
		return
	}
	pid, ok := parseParamUUID(c, "pid")
	if !ok {
		return
	}
	if err := h.service.DeletePasskey(pid, id); err != nil {
		pkg.HandleError(c, err)
		return
	}
	h.audit(c, audit.ActionM2MUserPasskeyRemoved, id, map[string]any{"passkey_id": pid})
	pkg.OK(c, gin.H{"message": "passkey removed"})
}

// --- Linked accounts ---

func (h *Handler) ListLinkedAccounts(c *gin.Context) {
	id, ok := parseUserID(c)
	if !ok {
		return
	}
	links, err := h.service.ListLinkedAccounts(id)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	pkg.OK(c, gin.H{"linked_accounts": links})
}

func (h *Handler) UnlinkAccount(c *gin.Context) {
	id, ok := parseUserID(c)
	if !ok {
		return
	}
	linkID, ok := parseParamUUID(c, "linkId")
	if !ok {
		return
	}
	if err := h.service.UnlinkAccount(linkID, id); err != nil {
		pkg.HandleError(c, err)
		return
	}
	h.audit(c, audit.ActionM2MUserLinkRemoved, id, map[string]any{"link_id": linkID})
	pkg.OK(c, gin.H{"message": "linked account removed"})
}
