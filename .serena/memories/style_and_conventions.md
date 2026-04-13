# OrionAuth - Code Style and Conventions

## Go Conventions
- Standard Go naming: PascalCase exported, camelCase unexported
- Package names: short, lowercase, single-word (user, oauth, mfa, rbac, audit, etc.)
- No test files present in the codebase yet

## Architecture Pattern
Each domain package follows a strict 3-layer pattern:
1. **Repository** (repository.go) — GORM queries only, returns (*Model, error) or (nil, nil) for not-found
2. **Service** (service.go) — Business logic, input validation, DTOs defined as structs with binding tags
3. **Handler** (handler.go) — HTTP handlers, JSON binding, calls pkg.HandleError() for error responses

### Constructor Pattern
```go
func NewService(repo *Repository, ...) *Service { return &Service{repo: repo, ...} }
func NewHandler(service *Service) *Handler { return &Handler{service: service} }
```

### Route Registration Pattern
```go
func (h *Handler) RegisterRoutes(public, authenticated *gin.RouterGroup) { ... }
```

## Error Handling
- **OAuthError**: RFC 6749 compliant (error, error_description, error_uri, status_code)
  - Constructors: ErrInvalidRequest(), ErrUnauthorizedClient(), ErrAccessDenied(), ErrInvalidGrant(), etc.
- **AppError**: Application-level (message, code, status_code)
  - Constructors: ErrBadRequest(), ErrNotFound(), ErrUnauthorized(), ErrForbidden(), ErrConflict(), ErrInternal(), etc.
- pkg.HandleError() routes errors by type to appropriate JSON response

## Response Helpers (pkg/response.go)
- pkg.JSON(), pkg.OK(), pkg.Created(), pkg.NoContent()
- pkg.Paginated() with PaginatedResponse struct
- pkg.ParsePagination() extracts page/per_page from query (defaults: 1/20, max per_page: 100)

## Logging
- log/slog (structured logging from Go stdlib)
- slog.Info, slog.Warn, slog.Error with key-value pairs

## Database Patterns
- GORM with PostgreSQL driver
- Repository returns (nil, nil) for not-found (gorm.ErrRecordNotFound handled gracefully)
- UpdateFields(id, map[string]any) for partial updates
- Transaction support via Repository.Transaction(fn)
- PostgreSQL-specific: pq.StringArray (TEXT[]), json.RawMessage (JSONB), INET for IPs

## Security Patterns
- Tokens never stored raw — only SHA-256 hashes in DB
- Passwords hashed with Argon2id, constant-time comparison (subtle.ConstantTimeCompare)
- RSA 2048-bit keys for JWT signing (RS256)
- PKCE S256 for public OAuth clients
- Refresh token rotation with family-based reuse detection
- No email enumeration (ForgotPassword always returns success)
- Account lockout after configurable failed attempts
- Rate limiting per IP (token bucket algorithm)

## ID Generation
- UUID v7 for entities (BaseModel.BeforeCreate hook)
- Opaque tokens: 32 random bytes → base64url (raw) + SHA-256 hex (stored)
- User codes (device flow): 8 uppercase chars, no vowels, format XXXX-XXXX

## JSON Conventions
- Sensitive fields tagged json:"-" (passwords, secrets, token hashes, backup codes)
- Optional fields use pointers (*string, *time.Time) with omitempty
- Handler responses use gin.H{} maps or model methods (PublicProfile(), AdminView())

## Cross-Service Dependencies
- Interfaces for loose coupling: IDTokenGenerator (OIDC→OAuth), MFAValidator (MFA→OAuth), email.Sender
- Set via SetXxx() methods after construction to break circular dependencies
