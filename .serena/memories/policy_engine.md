# OrionAuth - Policy Engine (OPA/Rego)

## Purpose
Policy-based authorization using embedded OPA/Rego to complement the existing RBAC system.
Policies provide dynamic, context-aware authorization (time, IP, user attributes) beyond static role checks.

## Package Structure
```
policy/
├── engine.go        # OPA compilation, cache (sync.RWMutex), evaluation
├── repository.go    # GORM CRUD for policies table
├── service.go       # Business logic, CRUD, TestPolicy, LoadAll, Evaluate (with audit on deny)
├── handler.go       # Gin HTTP handlers (CRUD + test + validate + replay)
├── input.go         # n/a — actual file: policy/inputs/inputs.go
├── middleware.go    # RequirePolicy middleware for admin API
└── adapter.go       # OAuthAdapter (implements oauth.PolicyEvaluator)
policy/inputs/
├── inputs.go        # Build*Input helpers used by every call site
└── schemas.go       # Per-type field catalog used by the admin UI autocomplete
```

## Model (model/policy.go)
- Policy: BaseModel + Name (unique), Description, Type, Rego (text), Version, Active, Priority
- Types whitelist (validated in CreatePolicyInput binding tag):
  `token_issuance | login | client_auth | admin_api | consent | refresh | introspect | device_approval | mfa | account_action | custom`

## Migration: 017_create_policies.sql
- Table policies + permissions policies:read, policies:write (granted to admin role)

## Engine Pattern
- PrepareForEval at load time, cache by type, sort by priority descending
- Evaluate: iterate policies of requested type, first deny wins, merge modify maps
- ValidateRego: compile without caching to check syntax
- EvaluateRaw: compile and evaluate ephemeral policy (for test endpoint)
- Rego convention: `package orionauth.<type>`, `default allow := true`, `deny[msg]`, `modify[key]`

## API Endpoints (under /api/v1/admin)
- POST /policies — Create (validates Rego before persist)
- GET /policies — List (optional ?type= filter)
- GET /policies/:id — Get by ID
- PATCH /policies/:id — Update (re-validates Rego, increments version)
- DELETE /policies/:id — Delete
- POST /policies/test — Test Rego with sample input
- POST /policies/validate — Validate Rego syntax only
- POST /policies/replay/:audit_log_id — Re-evaluate a captured deny against current policies

## Integration Hooks
1. **Login** (oauth/service.go AuthorizeLogin): evaluates `login` policies after authentication
2. **Token Issuance** (oauth/service.go issueTokensWithOpts): evaluates `token_issuance` policies, can deny or modify TTLs / scopes / claims
3. **Refresh** (oauth/service.go ExchangeRefreshToken): evaluates `refresh` policies; can narrow scopes via modify.scopes
4. **Consent** (oauth/service.go AuthorizeConsent): evaluates `consent` policies before persisting
5. **MFA gate** (oauth flow): evaluates `mfa` policies, modify.require_mfa overrides default
6. **Device approval** (oauth/service.go DeviceApprove): evaluates `device_approval` policies
7. **Introspect** (oauth /introspect): evaluates `introspect` policies; deny → returns inactive token per RFC 7662
8. **Client auth** (middleware): evaluates `client_auth` policies right after client credential validation
9. **Admin API** (policy/middleware.go RequirePolicy): evaluates `admin_api` policies after RBAC middleware
10. **Account self-service** (account/policy.go PolicyGate.Middleware): evaluates `account_action` policies on /api/v1/me/* sensitive routes

## Account Action policy type (added)
Input shape (see `policy/inputs/inputs.go::BuildAccountActionInput` and `policy/inputs/schemas.go`):
```
input.user.{id, email, email_verified, active, roles, permissions}
input.action               # update_profile | change_email | change_password | manage_mfa | manage_passkeys | manage_linked_accounts | delete_account
input.has_mfa              # bool
input.has_passkey          # bool (user-verified passkey)
input.account_age_days     # int
input.ip_address
input.user_agent
input.time.{hour, weekday, weekday_n, unix}
```
Only `deny[msg]` is consulted — modify is ignored. Errors fail open (action proceeds) so a broken policy can't lock a user out of their own account.

Example:
```rego
package orionauth.account_action

deny["email changes blocked after first 30 days"] {
    input.action == "change_email"
    input.account_age_days > 30
}

deny["account deletion blocked for admins"] {
    input.action == "delete_account"
    "admin" in input.user.roles
}
```

## Cross-Service Pattern
- `oauth.PolicyEvaluator` interface (avoids circular import)
- `policy.OAuthAdapter` implements it; wired via `oauthService.SetPolicyEvaluator(policy.NewOAuthAdapter(policyService))`
- `account.PolicyEvaluator` interface (same reason); adapter built inline in main.go (`accountPolicyEvaluatorAdapter`)
- `middleware.PolicyEvaluator` interface for client auth; adapter built inline in main.go (`policyDeciderAdapter`)

## Audit Actions
- `policy.created`, `policy.updated`, `policy.deleted`, `policy.denied` — `policy.denied` captures the full input so it can be replayed via POST /policies/replay/:id
