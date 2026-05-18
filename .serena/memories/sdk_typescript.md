# TypeScript SDK — `@orionauth/account-sdk`

A separate repo at `~/Git/orion-auth-account-sdk` ships a TypeScript SDK
wrapping the User Account API (`/api/v1/me/*`). Anyone consuming OrionAuth
from JS/TS apps should use it rather than re-rolling fetch wrappers.

- **Repo URL**: `https://git.nhsoul.fr/nhpro/orion-auth-account-sdk`
- **npm name**: `@orionauth/account-sdk` (scoped, public)
- **Sibling of**: orion-auth-backend / orion-auth-authui / orion-auth-frontend

## Surface

- `AccountClient` with modules: `profile`, `password`, `email`, `deletion`,
  `sessions`, `mfa`, `passkeys`, `linkedAccounts`, `reauth`.
- WebAuthn helpers under `@orionauth/account-sdk/webauthn` (base64url codec,
  navigator.credentials encoders/decoders, standalone `passkeyLogin()` for
  usernameless login).
- `withStepUp(fn, opts)` — auto-issues a reauth token on `403 reauth_required`
  and retries once.
- Optional `fromUserManager(userManager, { baseUrl })` integration with
  `oidc-client-ts` (peer dep, marked optional).
- Typed error classes: `AccountError`, `ReauthRequiredError`,
  `ReauthInvalidError`, `ConflictError`, `NotFoundError`, `ValidationError`,
  `UnauthorizedError`, `ForbiddenError`, `ServerError`.

## Keep in sync with the backend

Any change to `/api/v1/me/*` endpoint shape in this repo (request body,
response envelope, new endpoint, new permission, new error code) **must**
be mirrored in the SDK:

- Add/update DTOs in `src/types.ts`
- Update the relevant module in `src/modules/*.ts`
- Update tests in `tests/client.test.ts`
- Bump SDK version (semver) and changelog

In particular, the SDK considers these as the contract source of truth:
- `pkg.AppError` envelope: `{ message: string, code: string }` — used for
  every error response
- `X-Reauth-Token` header for step-up
- 403 error codes `reauth_required` / `reauth_invalid` (in middleware/reauth.go)
- The shape of `BeginRegistrationResponse` / `BeginLoginResponse` for passkeys
  is `{ challenge_id, options }` and `options` follows the WebAuthn
  PublicKeyCredentialCreationOptions / RequestOptions JSON spec.

## Tech stack of the SDK

TypeScript 5.7 strict · `tsup` (ESM+CJS+dts) · `vitest` (jsdom env, 53 tests,
89% line coverage, browser-only WebAuthn paths excluded) · `biome` for
lint/format · Forgejo CI (.forgejo/workflows/ci.yml + publish.yml on release).

## Quickstart

```ts
import { AccountClient } from '@orionauth/account-sdk'

const client = new AccountClient({
  baseUrl: 'https://auth.example.com',
  getAccessToken: async () => yourAccessToken,
})
await client.profile.get()
```

Or with `oidc-client-ts`:

```ts
import { fromUserManager } from '@orionauth/account-sdk/integrations/oidc-client-ts'
const client = fromUserManager(userManager, { baseUrl: 'https://auth.example.com' })
```
