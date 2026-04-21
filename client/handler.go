package client

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
	admin.POST("/clients", h.Create)
	admin.GET("/clients", h.List)
	admin.GET("/clients/:id", h.Get)
	admin.PATCH("/clients/:id", h.Update)
	admin.DELETE("/clients/:id", h.Delete)
	admin.POST("/clients/:id/rotate-secret", h.RotateSecret)
}

// Create godoc
// @Summary      Create a new OAuth client
// @Tags         Admin - Clients
// @Accept       json
// @Produce      json
// @Param        body body client.CreateInput true "Client creation payload"
// @Success      201 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/clients [post]
func (h *Handler) Create(c *gin.Context) {
	var input CreateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	resp, err := h.service.Create(input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionClientCreated, map[string]any{
			"client_name": input.Name,
		})
	}

	pkg.Created(c, resp)
}

// Get godoc
// @Summary      Get a client by ID
// @Tags         Admin - Clients
// @Produce      json
// @Param        id path string true "Client ID"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/clients/{id} [get]
func (h *Handler) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid client ID"))
		return
	}

	client, err := h.service.GetByID(id)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	pkg.OK(c, gin.H{"client": client})
}

// List godoc
// @Summary      List all clients
// @Tags         Admin - Clients
// @Produce      json
// @Param        page query int false "Page number"
// @Param        per_page query int false "Items per page"
// @Success      200 {object} pkg.PaginatedResponse
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/clients [get]
func (h *Handler) List(c *gin.Context) {
	page, perPage := pkg.ParsePagination(c)

	clients, total, err := h.service.List(page, perPage)
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to list clients"))
		return
	}

	pkg.Paginated(c, clients, total, page, perPage)
}

// Update godoc
// @Summary      Update a client
// @Tags         Admin - Clients
// @Accept       json
// @Produce      json
// @Param        id path string true "Client ID"
// @Param        body body client.UpdateInput true "Client update payload"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/clients/{id} [patch]
func (h *Handler) Update(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid client ID"))
		return
	}

	var input UpdateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}

	client, err := h.service.Update(id, input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionClientUpdated, map[string]any{
			"client_id": id,
		})
	}

	pkg.OK(c, gin.H{"client": client})
}

// Delete godoc
// @Summary      Delete a client
// @Tags         Admin - Clients
// @Produce      json
// @Param        id path string true "Client ID"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/clients/{id} [delete]
func (h *Handler) Delete(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid client ID"))
		return
	}

	if err := h.service.Delete(id); err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionClientDeleted, map[string]any{
			"client_id": id,
		})
	}

	pkg.OK(c, gin.H{"message": "client deleted"})
}

// RotateSecret godoc
// @Summary      Rotate a client's secret
// @Tags         Admin - Clients
// @Produce      json
// @Param        id path string true "Client ID"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/clients/{id}/rotate-secret [post]
func (h *Handler) RotateSecret(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid client ID"))
		return
	}

	secret, err := h.service.RotateSecret(id)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionClientSecretRotated, map[string]any{
			"client_id": id,
		})
	}

	pkg.OK(c, gin.H{"client_id": id, "client_secret": secret})
}
