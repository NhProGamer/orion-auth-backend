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
	pkg.Created(c, gin.H{"role": role})
}

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

func (h *Handler) ListRoles(c *gin.Context) {
	roles, err := h.service.ListRoles()
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to list roles"))
		return
	}
	pkg.OK(c, gin.H{"roles": roles})
}

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
	pkg.OK(c, gin.H{"role": role})
}

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
	pkg.OK(c, gin.H{"message": "role deleted"})
}

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
	pkg.OK(c, gin.H{"message": "permissions updated"})
}

func (h *Handler) ListPermissions(c *gin.Context) {
	perms, err := h.service.ListPermissions()
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to list permissions"))
		return
	}
	pkg.OK(c, gin.H{"permissions": perms})
}

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
	pkg.OK(c, gin.H{"message": "role assigned"})
}

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
	pkg.OK(c, gin.H{"message": "role removed"})
}

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
