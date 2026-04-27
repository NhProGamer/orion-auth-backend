package resource

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
	admin.POST("/resources", h.Create)
	admin.GET("/resources", h.List)
	admin.GET("/resources/:id", h.Get)
	admin.PATCH("/resources/:id", h.Update)
	admin.DELETE("/resources/:id", h.Delete)
	admin.POST("/resources/:id/permissions", h.AddPermission)
	admin.DELETE("/resources/:id/permissions/:permId", h.RemovePermission)
	admin.POST("/clients/:id/resource-permissions", h.SetClientPermissions)
	admin.GET("/clients/:id/resource-permissions", h.GetClientPermissions)
	admin.POST("/roles/:id/resource-permissions", h.SetRolePermissions)
	admin.GET("/roles/:id/resource-permissions", h.GetRolePermissions)
}

// Create godoc
// @Summary      Create a new API resource
// @Tags         Admin - Resources
// @Accept       json
// @Produce      json
// @Param        body body resource.CreateInput true "Resource creation payload"
// @Success      201 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      409 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/resources [post]
func (h *Handler) Create(c *gin.Context) {
	var input CreateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	res, err := h.service.Create(input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionResourceCreated, map[string]any{
			"resource_name": input.Name,
			"identifier":    input.Identifier,
		})
	}

	pkg.Created(c, gin.H{"resource": res})
}

// Get godoc
// @Summary      Get a resource by ID
// @Tags         Admin - Resources
// @Produce      json
// @Param        id path string true "Resource ID"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/resources/{id} [get]
func (h *Handler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid resource ID"))
		return
	}

	res, err := h.service.GetByID(id)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{"resource": res})
}

// List godoc
// @Summary      List all API resources
// @Tags         Admin - Resources
// @Produce      json
// @Param        page query int false "Page number"
// @Param        per_page query int false "Items per page"
// @Success      200 {object} pkg.PaginatedResponse
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/resources [get]
func (h *Handler) List(c *gin.Context) {
	page, perPage := pkg.ParsePagination(c)

	resources, total, err := h.service.List(page, perPage)
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to list resources"))
		return
	}

	pkg.Paginated(c, resources, total, page, perPage)
}

// Update godoc
// @Summary      Update a resource
// @Tags         Admin - Resources
// @Accept       json
// @Produce      json
// @Param        id path string true "Resource ID"
// @Param        body body resource.UpdateInput true "Resource update payload"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/resources/{id} [patch]
func (h *Handler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid resource ID"))
		return
	}

	var input UpdateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	res, err := h.service.Update(id, input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionResourceUpdated, map[string]any{
			"resource_id": id,
		})
	}

	pkg.OK(c, gin.H{"resource": res})
}

// Delete godoc
// @Summary      Delete a resource
// @Tags         Admin - Resources
// @Produce      json
// @Param        id path string true "Resource ID"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/resources/{id} [delete]
func (h *Handler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid resource ID"))
		return
	}

	if err := h.service.Delete(id); err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionResourceDeleted, map[string]any{
			"resource_id": id,
		})
	}

	pkg.OK(c, gin.H{"message": "resource deleted"})
}

// AddPermission godoc
// @Summary      Add a permission to a resource
// @Tags         Admin - Resources
// @Accept       json
// @Produce      json
// @Param        id path string true "Resource ID"
// @Param        body body resource.AddPermissionInput true "Permission payload"
// @Success      201 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/resources/{id}/permissions [post]
func (h *Handler) AddPermission(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid resource ID"))
		return
	}

	var input AddPermissionInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	perm, err := h.service.AddPermission(id, input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionResourcePermissionAdded, map[string]any{
			"resource_id":     id,
			"permission_name": input.Name,
		})
	}

	pkg.Created(c, gin.H{"permission": perm})
}

// RemovePermission godoc
// @Summary      Remove a permission from a resource
// @Tags         Admin - Resources
// @Produce      json
// @Param        id path string true "Resource ID"
// @Param        permId path string true "Permission ID"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/resources/{id}/permissions/{permId} [delete]
func (h *Handler) RemovePermission(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid resource ID"))
		return
	}

	permID, err := uuid.Parse(c.Param("permId"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid permission ID"))
		return
	}

	if err := h.service.RemovePermission(id, permID); err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionResourcePermissionRemoved, map[string]any{
			"resource_id":   id,
			"permission_id": permID,
		})
	}

	pkg.OK(c, gin.H{"message": "permission removed"})
}

// SetClientPermissions godoc
// @Summary      Set resource permissions for a client
// @Tags         Admin - Resources
// @Accept       json
// @Produce      json
// @Param        id path string true "Client ID"
// @Param        body body resource.SetClientPermissionsInput true "Permission IDs"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/clients/{id}/resource-permissions [post]
func (h *Handler) SetClientPermissions(c *gin.Context) {
	clientID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid client ID"))
		return
	}

	var input SetClientPermissionsInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	if err := h.service.SetClientPermissions(clientID, input); err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionClientPermissionsUpdated, map[string]any{
			"client_id":      clientID,
			"permission_ids": input.PermissionIDs,
		})
	}

	pkg.OK(c, gin.H{"message": "client permissions updated"})
}

// GetClientPermissions godoc
// @Summary      Get resource permissions for a client
// @Tags         Admin - Resources
// @Produce      json
// @Param        id path string true "Client ID"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/clients/{id}/resource-permissions [get]
func (h *Handler) GetClientPermissions(c *gin.Context) {
	clientID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid client ID"))
		return
	}

	perms, err := h.service.GetClientPermissions(clientID)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.List(c, perms, len(perms))
}

// SetRolePermissions godoc
// @Summary      Set resource permissions for a role
// @Tags         Admin - Resources
// @Accept       json
// @Produce      json
// @Param        id path string true "Role ID"
// @Param        body body resource.SetRolePermissionsInput true "Permission IDs"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/roles/{id}/resource-permissions [post]
func (h *Handler) SetRolePermissions(c *gin.Context) {
	roleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid role ID"))
		return
	}

	var input SetRolePermissionsInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	if err := h.service.SetRolePermissions(roleID, input); err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionClientPermissionsUpdated, map[string]any{
			"role_id":        roleID,
			"permission_ids": input.PermissionIDs,
		})
	}

	pkg.OK(c, gin.H{"message": "role resource permissions updated"})
}

// GetRolePermissions godoc
// @Summary      Get resource permissions for a role
// @Tags         Admin - Resources
// @Produce      json
// @Param        id path string true "Role ID"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/roles/{id}/resource-permissions [get]
func (h *Handler) GetRolePermissions(c *gin.Context) {
	roleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid role ID"))
		return
	}

	perms, err := h.service.GetRolePermissions(roleID)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.List(c, perms, len(perms))
}
