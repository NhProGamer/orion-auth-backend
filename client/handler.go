package client

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"OrionAuth/pkg"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(admin *gin.RouterGroup) {
	admin.POST("/clients", h.Create)
	admin.GET("/clients", h.List)
	admin.GET("/clients/:id", h.Get)
	admin.PATCH("/clients/:id", h.Update)
	admin.DELETE("/clients/:id", h.Delete)
	admin.POST("/clients/:id/rotate-secret", h.RotateSecret)
}

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

	pkg.Created(c, resp)
}

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

func (h *Handler) List(c *gin.Context) {
	page, perPage := pkg.ParsePagination(c)

	clients, total, err := h.service.List(page, perPage)
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to list clients"))
		return
	}

	pkg.Paginated(c, clients, total, page, perPage)
}

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

	pkg.OK(c, gin.H{"client": client})
}

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

	pkg.OK(c, gin.H{"message": "client deactivated"})
}

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

	pkg.OK(c, gin.H{"client_id": id, "client_secret": secret})
}
