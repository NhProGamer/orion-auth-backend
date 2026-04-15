package rbac

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/audit"
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

func (h *Handler) RegisterRoutes(admin *gin.RouterGroup) {
	admin.POST("/roles", h.CreateRole)
	admin.GET("/roles", h.ListRoles)
	admin.GET("/roles/:id", h.GetRole)
	admin.PATCH("/roles/:id", h.UpdateRole)
	admin.DELETE("/roles/:id", h.DeleteRole)
	admin.POST("/roles/:id/permissions", h.SetPermissions)
	admin.GET("/permissions", h.ListPermissions)
	admin.POST("/users/:id/roles", h.AssignRole)
	admin.DELETE("/users/:id/roles/:roleId", h.RemoveRole)
	admin.GET("/users/:id/roles", h.GetUserRoles)
}

// CreateRole godoc
// @Summary      Create a new role
// @Tags         Admin - RBAC
// @Accept       json
// @Produce      json
// @Param        body body rbac.CreateRoleInput true "Role creation payload"
// @Success      201 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/roles [post]
func (h *Handler) CreateRole(c *gin.Context) {
	var input CreateRoleInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	role, err := h.service.CreateRole(input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionRoleCreated, map[string]any{
			"role_id":   role.ID,
			"role_name": role.Name,
		})
	}

	pkg.Created(c, gin.H{"role": role})
}

// GetRole godoc
// @Summary      Get a role by ID
// @Tags         Admin - RBAC
// @Produce      json
// @Param        id path string true "Role ID"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/roles/{id} [get]
func (h *Handler) GetRole(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid role ID"))
		return
	}
	role, err := h.service.GetRole(id)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	pkg.OK(c, gin.H{"role": role})
}

// ListRoles godoc
// @Summary      List all roles
// @Tags         Admin - RBAC
// @Produce      json
// @Success      200 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/roles [get]
func (h *Handler) ListRoles(c *gin.Context) {
	roles, err := h.service.ListRoles()
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to list roles"))
		return
	}
	pkg.OK(c, gin.H{"roles": roles})
}

// UpdateRole godoc
// @Summary      Update a role
// @Tags         Admin - RBAC
// @Accept       json
// @Produce      json
// @Param        id path string true "Role ID"
// @Param        body body rbac.UpdateRoleInput true "Role update payload"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/roles/{id} [patch]
func (h *Handler) UpdateRole(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid role ID"))
		return
	}
	var input UpdateRoleInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	role, err := h.service.UpdateRole(id, input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionRoleUpdated, map[string]any{
			"role_id": id,
		})
	}

	pkg.OK(c, gin.H{"role": role})
}

// DeleteRole godoc
// @Summary      Delete a role
// @Tags         Admin - RBAC
// @Produce      json
// @Param        id path string true "Role ID"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/roles/{id} [delete]
func (h *Handler) DeleteRole(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid role ID"))
		return
	}
	if err := h.service.DeleteRole(id); err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionRoleDeleted, map[string]any{
			"role_id": id,
		})
	}

	pkg.OK(c, gin.H{"message": "role deleted"})
}

// SetPermissions godoc
// @Summary      Set permissions for a role
// @Tags         Admin - RBAC
// @Accept       json
// @Produce      json
// @Param        id path string true "Role ID"
// @Param        body body rbac.SetPermissionsInput true "Permissions payload"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/roles/{id}/permissions [post]
func (h *Handler) SetPermissions(c *gin.Context) {
	roleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid role ID"))
		return
	}
	var input SetPermissionsInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	if err := h.service.SetRolePermissions(roleID, input.PermissionIDs); err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionRolePermissionsUpdated, map[string]any{
			"role_id":        roleID,
			"permission_ids": input.PermissionIDs,
		})
	}

	pkg.OK(c, gin.H{"message": "permissions updated"})
}

// ListPermissions godoc
// @Summary      List all permissions
// @Tags         Admin - RBAC
// @Produce      json
// @Success      200 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/permissions [get]
func (h *Handler) ListPermissions(c *gin.Context) {
	perms, err := h.service.ListPermissions()
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to list permissions"))
		return
	}
	pkg.OK(c, gin.H{"permissions": perms})
}

// AssignRole godoc
// @Summary      Assign a role to a user
// @Tags         Admin - RBAC
// @Accept       json
// @Produce      json
// @Param        id path string true "User ID"
// @Param        body body rbac.AssignRoleInput true "Role assignment payload"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/users/{id}/roles [post]
func (h *Handler) AssignRole(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid user ID"))
		return
	}
	var input AssignRoleInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	if err := h.service.AssignRole(userID, input.RoleID); err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionRoleAssigned, map[string]any{
			"target_user_id": userID,
			"role_id":        input.RoleID,
		})
	}

	pkg.OK(c, gin.H{"message": "role assigned"})
}

// RemoveRole godoc
// @Summary      Remove a role from a user
// @Tags         Admin - RBAC
// @Produce      json
// @Param        id path string true "User ID"
// @Param        roleId path string true "Role ID"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/users/{id}/roles/{roleId} [delete]
func (h *Handler) RemoveRole(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid user ID"))
		return
	}
	roleID, err := uuid.Parse(c.Param("roleId"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid role ID"))
		return
	}
	if err := h.service.RemoveRole(userID, roleID); err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionRoleRemoved, map[string]any{
			"target_user_id": userID,
			"role_id":        roleID,
		})
	}

	pkg.OK(c, gin.H{"message": "role removed"})
}

// GetUserRoles godoc
// @Summary      Get roles assigned to a user
// @Tags         Admin - RBAC
// @Produce      json
// @Param        id path string true "User ID"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/users/{id}/roles [get]
func (h *Handler) GetUserRoles(c *gin.Context) {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid user ID"))
		return
	}
	roles, err := h.service.GetUserRoles(userID)
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to get user roles"))
		return
	}
	pkg.OK(c, gin.H{"roles": roles})
}
