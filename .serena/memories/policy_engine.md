# OrionAuth - Policy Engine (OPA/Rego)

## Purpose
Policy-based authorization using embedded OPA/Rego to complement the existing RBAC system.
Policies provide dynamic, context-aware authorization (time, IP, user attributes) beyond static role checks.

## Package Structure
```
policy/
├── engine.go       # OPA compilation, cache (sync.RWMutex), evaluation
├── repository.go   # GORM CRUD for policies table
├── service.go      # Business logic, CRUD, TestPolicy, LoadAll, Evaluate
├── handler.go      # Gin HTTP handlers (CRUD + test + validate)
├── input.go        # Input builders for different policy types
├── middleware.go    # RequirePolicy middleware for admin API
└── adapter.go      # OAuthAdapter (implements oauth.PolicyEvaluator)
```

## Model (model/policy.go)
- Policy: BaseModel + Name (unique), Description, Type, Rego (text), Version, Active, Priority
- Types: token_issuance, login, client_auth, admin_api, custom

## Migration: 017_create_policies.sql
- Table policies + permissions policies:read, policies:write (granted to admin role)

## Engine Pattern
- PrepareForEval at load time, cache by type, sort by priority descending
- Evaluate: iterate policies of requested type, first deny wins, merge modify maps
- ValidateRego: compile without caching to check syntax
- EvaluateRaw: compile and evaluate ephemeral policy (for test endpoint)
- Rego convention: package orionauth.<type>, default allow := true, deny[msg], modify[key]

## API Endpoints (under /api/v1/admin)
- POST /policies — Create (validates Rego before persist)
- GET /policies — List (optional ?type= filter)
- GET /policies/:id — Get by ID
- PATCH /policies/:id — Update (re-validates Rego, increments version)
- DELETE /policies/:id — Delete
- POST /policies/test — Test Rego with sample input
- POST /policies/validate — Validate Rego syntax only

## Integration Hooks
1. **Login** (oauth/service.go AuthorizeLogin): evaluates login policies after authentication
2. **Token Issuance** (oauth/service.go issueTokensWithOpts): evaluates token_issuance policies, can deny or modify TTLs
3. **Admin API** (policy/middleware.go RequirePolicy): evaluates admin_api policies after RBAC middleware

## Cross-Service Pattern
- oauth.PolicyEvaluator interface (avoids circular import)
- policy.OAuthAdapter implements it, converts policy.EvalResult → oauth.PolicyResult
- Connected via oauthService.SetPolicyEvaluator(policy.NewOAuthAdapter(policyService)) in main.go

## Audit Actions
- policy.created, policy.updated, policy.deleted, policy.denied
