package policy

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"orion-auth-backend/audit"
	"orion-auth-backend/pkg"
	"orion-auth-backend/policy/inputs"
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
	admin.GET("/policies/schemas", h.GetSchemas)
	admin.GET("/policies/stats", h.GetStats)
	admin.POST("/policies/replay", h.Replay)
	admin.GET("/policies/:id", h.GetPolicy)
	admin.PATCH("/policies/:id", h.UpdatePolicy)
	admin.DELETE("/policies/:id", h.DeletePolicy)
	admin.POST("/policies/test", h.TestPolicy)
	admin.POST("/policies/validate", h.ValidatePolicy)
}

// GetSchemas godoc
// @Summary      Per-type input/modify field catalog for autocomplete
// @Tags         Admin - Policies
// @Produce      json
// @Success      200 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/policies/schemas [get]
func (h *Handler) GetSchemas(c *gin.Context) {
	pkg.OK(c, gin.H{"data": inputs.Schemas()})
}

// Replay godoc
// @Summary      Re-evaluate a past denial against current policies
// @Tags         Admin - Policies
// @Accept       json
// @Produce      json
// @Param        body body object true "Replay payload {audit_log_id}"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Failure      404 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/policies/replay [post]
func (h *Handler) Replay(c *gin.Context) {
	var body struct {
		AuditLogID string `json:"audit_log_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid request body: "+err.Error()))
		return
	}
	id, err := uuid.Parse(body.AuditLogID)
	if err != nil {
		pkg.HandleError(c, pkg.ErrBadRequest("invalid audit_log_id"))
		return
	}
	result, err := h.service.Replay(id)
	if err != nil {
		pkg.HandleError(c, err)
		return
	}
	pkg.OK(c, result)
}

// GetStats godoc
// @Summary      Aggregated stats on policy denials
// @Tags         Admin - Policies
// @Produce      json
// @Param        days query int false "Window size in days (default 7)"
// @Param        limit query int false "Top-N + recent items cap (default 10)"
// @Success      200 {object} map[string]any
// @Security     BearerAuth
// @Router       /api/v1/admin/policies/stats [get]
func (h *Handler) GetStats(c *gin.Context) {
	days := parseIntQuery(c, "days", 7)
	limit := parseIntQuery(c, "limit", 10)
	stats, err := h.service.GetStats(days, limit)
	if err != nil {
		pkg.HandleError(c, pkg.ErrInternal("failed to compute stats"))
		return
	}
	pkg.OK(c, stats)
}

func parseIntQuery(c *gin.Context, key string, def int) int {
	raw := c.Query(key)
	if raw == "" {
		return def
	}
	n := 0
	for _, ch := range raw {
		if ch < '0' || ch > '9' {
			return def
		}
		n = n*10 + int(ch-'0')
	}
	if n == 0 {
		return def
	}
	return n
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
