package policy

import (
	"context"
	"log/slog"

	"github.com/google/uuid"

	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
)

type Service struct {
	repo   RepositoryInterface
	engine *Engine
}

func NewService(repo RepositoryInterface, engine *Engine) *Service {
	return &Service{repo: repo, engine: engine}
}

// --- Input DTOs ---

type CreatePolicyInput struct {
	Name        string  `json:"name" binding:"required"`
	Description *string `json:"description"`
	Type        string  `json:"type" binding:"required,oneof=token_issuance login client_auth admin_api custom"`
	Rego        string  `json:"rego" binding:"required"`
	Priority    *int    `json:"priority"`
	Active      *bool   `json:"active"`
}

type UpdatePolicyInput struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Rego        *string `json:"rego"`
	Priority    *int    `json:"priority"`
	Active      *bool   `json:"active"`
}

type TestPolicyInput struct {
	Rego  string         `json:"rego" binding:"required"`
	Input map[string]any `json:"input" binding:"required"`
}

type TestPolicyResult struct {
	Allow      bool           `json:"allow"`
	Deny       bool           `json:"deny"`
	DenyReason string         `json:"deny_reason,omitempty"`
	Modify     map[string]any `json:"modify,omitempty"`
	Error      string         `json:"error,omitempty"`
}

// --- CRUD ---

func (s *Service) CreatePolicy(input CreatePolicyInput) (*model.Policy, error) {
	existing, _ := s.repo.FindByName(input.Name)
	if existing != nil {
		return nil, pkg.ErrConflict("policy name already exists")
	}

	if err := s.engine.ValidateRego(input.Rego); err != nil {
		return nil, pkg.ErrBadRequest(err.Error())
	}

	p := &model.Policy{
		Name:        input.Name,
		Description: input.Description,
		Type:        input.Type,
		Rego:        input.Rego,
		Version:     1,
		Active:      true,
		Priority:    0,
	}
	if input.Priority != nil {
		p.Priority = *input.Priority
	}
	if input.Active != nil {
		p.Active = *input.Active
	}

	if err := s.repo.Create(p); err != nil {
		return nil, pkg.ErrInternal("failed to create policy")
	}

	if p.Active {
		if err := s.engine.LoadPolicy(*p); err != nil {
			slog.Warn("failed to load policy into engine", "policy_id", p.ID, "error", err)
		}
	}

	slog.Info("policy created", "policy_id", p.ID, "name", p.Name, "type", p.Type)
	return p, nil
}

func (s *Service) GetPolicy(id uuid.UUID) (*model.Policy, error) {
	p, err := s.repo.FindByID(id)
	if err != nil {
		return nil, pkg.ErrInternal("failed to find policy")
	}
	if p == nil {
		return nil, pkg.ErrNotFound("policy not found")
	}
	return p, nil
}

func (s *Service) ListPolicies(policyType string) ([]model.Policy, error) {
	if policyType != "" {
		return s.repo.ListByType(policyType)
	}
	return s.repo.List()
}

func (s *Service) UpdatePolicy(id uuid.UUID, input UpdatePolicyInput) (*model.Policy, error) {
	p, err := s.GetPolicy(id)
	if err != nil {
		return nil, err
	}

	if input.Rego != nil {
		if err := s.engine.ValidateRego(*input.Rego); err != nil {
			return nil, pkg.ErrBadRequest(err.Error())
		}
		p.Rego = *input.Rego
		p.Version++
	}
	if input.Name != nil {
		p.Name = *input.Name
	}
	if input.Description != nil {
		p.Description = input.Description
	}
	if input.Priority != nil {
		p.Priority = *input.Priority
	}
	if input.Active != nil {
		p.Active = *input.Active
	}

	if err := s.repo.Update(p); err != nil {
		return nil, pkg.ErrInternal("failed to update policy")
	}

	// Update engine cache
	if p.Active {
		if err := s.engine.LoadPolicy(*p); err != nil {
			slog.Warn("failed to reload policy into engine", "policy_id", p.ID, "error", err)
		}
	} else {
		s.engine.RemovePolicy(p.ID, p.Type)
	}

	slog.Info("policy updated", "policy_id", p.ID, "name", p.Name)
	return p, nil
}

func (s *Service) DeletePolicy(id uuid.UUID) error {
	p, err := s.GetPolicy(id)
	if err != nil {
		return err
	}

	if err := s.repo.Delete(id); err != nil {
		return pkg.ErrInternal("failed to delete policy")
	}

	s.engine.RemovePolicy(id, p.Type)
	slog.Info("policy deleted", "policy_id", id, "name", p.Name)
	return nil
}

// --- Test & Validate ---

func (s *Service) TestPolicy(input TestPolicyInput) (*TestPolicyResult, error) {
	result, err := s.engine.EvaluateRaw(context.Background(), input.Rego, input.Input)
	if err != nil {
		return &TestPolicyResult{Error: err.Error()}, nil
	}
	return &TestPolicyResult{
		Allow:      result.Allow,
		Deny:       result.Deny,
		DenyReason: result.DenyReason,
		Modify:     result.Modify,
	}, nil
}

func (s *Service) ValidateRego(rego string) error {
	return s.engine.ValidateRego(rego)
}

// --- Evaluation ---

func (s *Service) Evaluate(ctx context.Context, policyType string, input map[string]any) (*EvalResult, error) {
	return s.engine.Evaluate(ctx, policyType, input)
}

// --- Startup ---

func (s *Service) LoadAll() error {
	policies, err := s.repo.ListAllActive()
	if err != nil {
		return err
	}
	if len(policies) == 0 {
		return nil
	}
	slog.Info("loading policies into engine", "count", len(policies))
	return s.engine.LoadPolicies(policies)
}
