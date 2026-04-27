package policy

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
	admin.POST("/policies", h.CreatePolicy)
	admin.GET("/policies", h.ListPolicies)
	admin.GET("/policies/:id", h.GetPolicy)
	admin.PATCH("/policies/:id", h.UpdatePolicy)
	admin.DELETE("/policies/:id", h.DeletePolicy)
	admin.POST("/policies/test", h.TestPolicy)
	admin.POST("/policies/validate", h.ValidatePolicy)
}

// CreatePolicy godoc
// @Summary      Create a new policy
// @Tags         Admin - Policies
// @Accept       json
// @Produce      json
// @Param        body body policy.CreatePolicyInput true "Policy creation payload"
// @Success      201 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      409 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/policies [post]
func (h *Handler) CreatePolicy(c *gin.Context) {
	var input CreatePolicyInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	p, err := h.service.CreatePolicy(input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionPolicyCreated, map[string]any{
			"policy_id":   p.ID,
			"policy_name": p.Name,
			"policy_type": p.Type,
		})
	}

	pkg.Created(c, gin.H{"policy": p})
}

// GetPolicy godoc
// @Summary      Get a policy by ID
// @Tags         Admin - Policies
// @Produce      json
// @Param        id path string true "Policy ID"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/policies/{id} [get]
func (h *Handler) GetPolicy(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid policy ID"))
		return
	}
	p, err := h.service.GetPolicy(id)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	pkg.OK(c, gin.H{"policy": p})
}

// ListPolicies godoc
// @Summary      List all policies
// @Tags         Admin - Policies
// @Produce      json
// @Param        type query string false "Filter by policy type"
// @Success      200 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/policies [get]
func (h *Handler) ListPolicies(c *gin.Context) {
	policyType := c.Query("type")
	policies, err := h.service.ListPolicies(policyType)
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to list policies"))
		return
	}
	pkg.List(c, policies, len(policies))
}

// UpdatePolicy godoc
// @Summary      Update a policy
// @Tags         Admin - Policies
// @Accept       json
// @Produce      json
// @Param        id path string true "Policy ID"
// @Param        body body policy.UpdatePolicyInput true "Policy update payload"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/policies/{id} [patch]
func (h *Handler) UpdatePolicy(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid policy ID"))
		return
	}
	var input UpdatePolicyInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	p, err := h.service.UpdatePolicy(id, input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionPolicyUpdated, map[string]any{
			"policy_id": id,
		})
	}

	pkg.OK(c, gin.H{"policy": p})
}

// DeletePolicy godoc
// @Summary      Delete a policy
// @Tags         Admin - Policies
// @Produce      json
// @Param        id path string true "Policy ID"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/policies/{id} [delete]
func (h *Handler) DeletePolicy(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid policy ID"))
		return
	}
	if err := h.service.DeletePolicy(id); err != nil {
		pkg.HandleError(c, err)
		return
	}

	if h.auditService != nil {
		h.auditService.LogFromContext(c, audit.ActionPolicyDeleted, map[string]any{
			"policy_id": id,
		})
	}

	pkg.OK(c, gin.H{"message": "policy deleted"})
}

// TestPolicy godoc
// @Summary      Test a Rego policy with sample input
// @Tags         Admin - Policies
// @Accept       json
// @Produce      json
// @Param        body body policy.TestPolicyInput true "Test payload"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/policies/test [post]
func (h *Handler) TestPolicy(c *gin.Context) {
	var input TestPolicyInput
	if err := c.ShouldBindJSON(&input); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	result, err := h.service.TestPolicy(input)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	pkg.OK(c, gin.H{"result": result})
}

// ValidatePolicy godoc
// @Summary      Validate Rego syntax
// @Tags         Admin - Policies
// @Accept       json
// @Produce      json
// @Param        body body map[string]string true "Rego code"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/policies/validate [post]
func (h *Handler) ValidatePolicy(c *gin.Context) {
	var body struct {
		Rego string `json:"rego" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	if err := h.service.ValidateRego(body.Rego); err != nil {
		pkg.OK(c, gin.H{"valid": false, "error": err.Error()})
		return
	}
	pkg.OK(c, gin.H{"valid": true})
}
