package policy

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/v1/rego"

	"orion-auth-backend/model"
)

// EvalResult holds the result of a policy evaluation.
type EvalResult struct {
	Allow      bool           `json:"allow"`
	Deny       bool           `json:"deny"`
	DenyReason string         `json:"deny_reason,omitempty"`
	Modify     map[string]any `json:"modify,omitempty"`
	PolicyName string         `json:"policy_name,omitempty"`
}

type preparedPolicy struct {
	id          uuid.UUID
	name        string
	priority    int
	allowQuery  rego.PreparedEvalQuery
	denyQuery   *rego.PreparedEvalQuery
	modifyQuery *rego.PreparedEvalQuery
}

// Engine manages compiled OPA policies and evaluates them.
type Engine struct {
	mu       sync.RWMutex
	prepared map[string][]preparedPolicy // key: policy type
}

// NewEngine creates a new policy engine.
func NewEngine() *Engine {
	return &Engine{
		prepared: make(map[string][]preparedPolicy),
	}
}

// LoadPolicies compiles all provided policies and caches them by type.
func (e *Engine) LoadPolicies(policies []model.Policy) error {
	grouped := make(map[string][]preparedPolicy)

	for _, p := range policies {
		pp, err := e.compile(p)
		if err != nil {
			return fmt.Errorf("failed to compile policy %q: %w", p.Name, err)
		}
		grouped[p.Type] = append(grouped[p.Type], pp)
	}

	// Sort each group by priority descending
	for _, pps := range grouped {
		sortByPriority(pps)
	}

	e.mu.Lock()
	e.prepared = grouped
	e.mu.Unlock()
	return nil
}

// LoadPolicy compiles and adds/replaces a single policy in the cache.
func (e *Engine) LoadPolicy(p model.Policy) error {
	pp, err := e.compile(p)
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	policies := e.prepared[p.Type]

	// Replace if exists
	found := false
	for i, existing := range policies {
		if existing.id == p.ID {
			policies[i] = pp
			found = true
			break
		}
	}
	if !found {
		policies = append(policies, pp)
	}

	sortByPriority(policies)
	e.prepared[p.Type] = policies
	return nil
}

// RemovePolicy removes a policy from the cache.
func (e *Engine) RemovePolicy(id uuid.UUID, policyType string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	policies := e.prepared[policyType]
	for i, p := range policies {
		if p.id == id {
			e.prepared[policyType] = append(policies[:i], policies[i+1:]...)
			return
		}
	}
}

// Evaluate runs all active policies of the given type against the input.
// Returns allow if no policies exist for the type (fail-open).
func (e *Engine) Evaluate(ctx context.Context, policyType string, input map[string]any) (*EvalResult, error) {
	e.mu.RLock()
	policies := e.prepared[policyType]
	e.mu.RUnlock()

	if len(policies) == 0 {
		return &EvalResult{Allow: true}, nil
	}

	merged := make(map[string]any)

	for _, p := range policies {
		// Check deny
		if p.denyQuery != nil {
			rs, err := p.denyQuery.Eval(ctx, rego.EvalInput(input))
			if err != nil {
				return nil, fmt.Errorf("policy %q deny evaluation failed: %w", p.name, err)
			}
			if len(rs) > 0 {
				if denyVal, ok := rs[0].Bindings["x"]; ok {
					reason := extractDenyReason(denyVal)
					if reason != "" {
						return &EvalResult{
							Deny:       true,
							DenyReason: reason,
							PolicyName: p.name,
						}, nil
					}
				}
			}
		}

		// Collect modify
		if p.modifyQuery != nil {
			rs, err := p.modifyQuery.Eval(ctx, rego.EvalInput(input))
			if err == nil && len(rs) > 0 {
				if modVal, ok := rs[0].Bindings["x"]; ok {
					if modMap, ok := modVal.(map[string]any); ok {
						for k, v := range modMap {
							merged[k] = v
						}
					}
				}
			}
		}
	}

	result := &EvalResult{Allow: true}
	if len(merged) > 0 {
		result.Modify = merged
	}
	return result, nil
}

// ValidateRego compiles a Rego module without caching to check syntax.
func (e *Engine) ValidateRego(regoCode string) error {
	_, err := rego.New(
		rego.Module("validation.rego", regoCode),
		rego.Query("data"),
	).PrepareForEval(context.Background())
	if err != nil {
		return fmt.Errorf("invalid rego: %w", err)
	}
	return nil
}

// EvaluateRaw compiles and evaluates a Rego module with the given input (for testing).
func (e *Engine) EvaluateRaw(ctx context.Context, regoCode string, input map[string]any) (*EvalResult, error) {
	pkgPath := extractPackagePath(regoCode)

	// Validate compilation first
	if err := e.ValidateRego(regoCode); err != nil {
		return nil, fmt.Errorf("compilation failed: %w", err)
	}

	evalBinding := func(field string) (any, error) {
		q := fmt.Sprintf("x = %s.%s", pkgPath, field)
		prepared, err := rego.New(
			rego.Module("test.rego", regoCode),
			rego.Query(q),
		).PrepareForEval(ctx)
		if err != nil {
			return nil, err
		}
		rs, err := prepared.Eval(ctx, rego.EvalInput(input))
		if err != nil || len(rs) == 0 {
			return nil, err
		}
		return rs[0].Bindings["x"], nil
	}

	result := &EvalResult{Allow: true}

	if allowVal, err := evalBinding("allow"); err == nil && allowVal != nil {
		if b, ok := allowVal.(bool); ok {
			result.Allow = b
		}
	}

	if denyVal, err := evalBinding("deny"); err == nil && denyVal != nil {
		reason := extractDenyReason(denyVal)
		if reason != "" {
			result.Allow = false
			result.Deny = true
			result.DenyReason = reason
		}
	}

	if modVal, err := evalBinding("modify"); err == nil && modVal != nil {
		if modMap, ok := modVal.(map[string]any); ok && len(modMap) > 0 {
			result.Modify = modMap
		}
	}

	return result, nil
}

// extractDenyReason extracts the first deny reason from OPA evaluation results.
// OPA may return deny as []any (array), map[any]any (set), or other types.
func extractDenyReason(denyVal any) string {
	switch v := denyVal.(type) {
	case []any:
		if len(v) > 0 {
			return fmt.Sprintf("%v", v[0])
		}
	case map[string]any:
		for k := range v {
			return k
		}
	default:
		s := fmt.Sprintf("%v", v)
		if s != "" && s != "[]" && s != "map[]" {
			return s
		}
	}
	return ""
}

// extractPackagePath parses the package declaration from Rego source code.
func extractPackagePath(regoCode string) string {
	for _, line := range strings.Split(regoCode, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "package ") {
			pkg := strings.TrimPrefix(trimmed, "package ")
			return "data." + strings.TrimSpace(pkg)
		}
	}
	return "data"
}

func (e *Engine) compile(p model.Policy) (preparedPolicy, error) {
	moduleName := fmt.Sprintf("policy_%s.rego", p.ID.String())
	basePath := fmt.Sprintf("data.orionauth.%s", p.Type)

	// Compile allow query (always required)
	allowQuery, err := rego.New(
		rego.Module(moduleName, p.Rego),
		rego.Query(fmt.Sprintf("x = %s.allow", basePath)),
	).PrepareForEval(context.Background())
	if err != nil {
		return preparedPolicy{}, fmt.Errorf("compilation failed for %q: %w", p.Name, err)
	}

	pp := preparedPolicy{
		id:         p.ID,
		name:       p.Name,
		priority:   p.Priority,
		allowQuery: allowQuery,
	}

	// Compile deny query (optional — may not be defined)
	if denyQuery, err := rego.New(
		rego.Module(moduleName, p.Rego),
		rego.Query(fmt.Sprintf("x = %s.deny", basePath)),
	).PrepareForEval(context.Background()); err == nil {
		pp.denyQuery = &denyQuery
	}

	// Compile modify query (optional — may not be defined)
	if modQuery, err := rego.New(
		rego.Module(moduleName, p.Rego),
		rego.Query(fmt.Sprintf("x = %s.modify", basePath)),
	).PrepareForEval(context.Background()); err == nil {
		pp.modifyQuery = &modQuery
	}

	return pp, nil
}

func sortByPriority(policies []preparedPolicy) {
	sort.Slice(policies, func(i, j int) bool {
		return policies[i].priority > policies[j].priority
	})
}
