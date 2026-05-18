# Go SDK — `orion-auth-m2m-sdk-go`

A separate repo at `~/Git/orion-auth-m2m-sdk-go` ships a Go SDK that wraps
the M2M admin API (`/api/v1/m2m/users/*`). Services written in Go consume it
to provision/update/delete users programmatically.

- **Repo URL**: `https://git.nhsoul.fr/nhpro/orion-auth-m2m-sdk-go`
- **Module path** (= Go import path): `git.nhsoul.fr/nhpro/orion-auth-m2m-sdk-go`
- **Package**: `orionauthm2m`
- **Go baseline**: 1.23
- Sibling of: orion-auth-backend, orion-auth-authui, orion-auth-frontend,
  orion-auth-account-sdk (TypeScript)

## Surface

- `Client` constructed via `New(Config{ BaseURL, Issuer, ClientID, ClientSecret, Scopes })`
- OAuth Client Credentials handled internally via
  `golang.org/x/oauth2/clientcredentials` with `audience=urn:orion:m2m`
  passed as an `EndpointParam` (RFC 8707). Token caching + silent refresh
  are transparent.
- `client.Users()` exposes CRUD + auth ops + sub-services:
  - `Roles()`, `Sessions()`, `Passkeys()`, `LinkedAccounts()`
- Typed errors: `APIError` + 7 sentinels (`ErrNotFound`, `ErrConflict`,
  `ErrUnauthorized`, `ErrValidation`, `ErrM2MOnly`, `ErrWrongAudience`,
  `ErrInsufficientScope`, `ErrServer`) — work with `errors.Is`.
- Pagination: `ListPage(ctx, page, perPage)` + `Iterate(ctx, batchSize, fn)`.

## Keep in sync with the backend

Any change to `/api/v1/m2m/users/*` endpoint shape (request body, response
envelope, new endpoint, new permission, new error code) **must** be mirrored:
- Add/update DTOs in `types.go`
- Update the relevant `users_*.go` file
- Update tests in `users_test.go` / `users_subservices_test.go`
- Bump SDK version (semver) + CHANGELOG.md
- Push a `v*` tag — Go module clients pick up the version directly from git

## Tech stack of the SDK

Go 1.23 strict · stdlib only for HTTP/JSON/tests · single external dep
`golang.org/x/oauth2/clientcredentials` · `net/http/httptest` for tests
(coverage ~86%) · Forgejo CI (`.forgejo/workflows/ci.yml`).

## Quickstart

```go
import (
    "context"
    orionauthm2m "git.nhsoul.fr/nhpro/orion-auth-m2m-sdk-go"
)

c, _ := orionauthm2m.New(orionauthm2m.Config{
    BaseURL:      "https://auth.example.com",
    Issuer:       "https://auth.example.com",
    ClientID:     "...",
    ClientSecret: "...",
    Scopes:       []string{"m2m:users:read", "m2m:users:write"},
})
res, err := c.Users().Create(ctx, &orionauthm2m.CreateUserParams{
    Email: "alice@example.com",
})
// res.User + res.GeneratedPassword (if Password was nil)
```

## Companion SDKs

- TypeScript (`@orionauth/account-sdk`): User Account API (`/me/*`), see
  memory `sdk_typescript`.
- Go (`orion-auth-m2m-sdk-go`): M2M admin API (`/m2m/users/*`), this memory.
- Future: `orion-auth-m2m-sdk-ts` for M2M in TS, or `orion-auth-account-sdk-go`
  for Account API in Go — same naming pattern.
