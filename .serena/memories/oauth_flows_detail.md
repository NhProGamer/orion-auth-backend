# OrionAuth - OAuth2 Flows Implementation Detail

## 1. Authorization Code Grant (with PKCE)
**Flow**: GET /authorize → POST /authorize/login → POST /authorize/mfa (optional) → POST /authorize/consent → POST /token

### Step 1: InitAuthorize (GET /authorize)
- Query params: client_id, redirect_uri, response_type, scope, state, nonce, code_challenge, code_challenge_method
- Validates client, redirect URI, response type, scopes
- Creates AuthorizationRequest in DB (expires per AuthCodeTTL)
- Returns: RequestID, ClientName, ClientID, ScopesRequested, RequiresLogin, RequiresConsent

### Step 2: AuthorizeLogin (POST /authorize/login)
- Input: RequestID, Email, Password
- Authenticates user, checks existing consent and MFA requirement
- Updates AuthorizationRequest with UserID, Authenticated flag
- Returns: RequestID, Authenticated, RequiresConsent, RequiresMFA, Scopes

### Step 3: AuthorizeMFA (POST /authorize/mfa) — optional
- Input: RequestID, Code
- Validates TOTP/backup code
- Returns same as AuthorizeLogin response

### Step 4: AuthorizeConsent (POST /authorize/consent)
- Input: RequestID, ScopesGranted
- Stores/updates consent record
- For first-party clients: auto-completes without consent (CompleteAuthorizeFirstParty)
- Generates authorization code (hash stored, raw returned)
- Creates session
- Returns: RedirectURI, Code, State

### Step 5: ExchangeAuthorizationCode (POST /token, grant_type=authorization_code)
- Input: code, redirect_uri, code_verifier (PKCE), client auth
- Validates: code not used, not expired, client matches, redirect matches
- PKCE: Verifies code_verifier against stored code_challenge (S256 only)
- Replay detection: if code already used, revokes all session tokens
- Issues: access_token + refresh_token + id_token (if openid scope)
- Token response: access_token, token_type, expires_in, refresh_token, id_token, scope

## 2. Client Credentials Grant
**POST /token, grant_type=client_credentials**
- Only for confidential clients (rejects public)
- No user context (no userID, no session, no refresh token)
- Issues access token only
- Scope validated against client's allowed scopes

## 3. Refresh Token Grant
**POST /token, grant_type=refresh_token**
- Input: refresh_token, scope (optional subset)
- Token rotation: old RT marked as rotated, new RT issued in new family
- Reuse detection: if RT was already rotated → revokes entire family (compromise mitigation)
- Cascades: old access tokens revoked when RT rotated
- Scope downscoping: requested scopes must be subset of original
- Issues new access_token + refresh_token + id_token

## 4. Device Code Grant (RFC 8628)
**Phase 1: Device requests code**
- POST /device_authorization (client auth required)
- Generates device_code (opaque, hashed for storage) + user_code (XXXX-XXXX format, no vowels)
- Returns: device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval

**Phase 2: User verifies in browser**
- POST /device/verify — Input: UserCode → Returns: UserCode, ClientName, Scopes
- POST /device/approve — Input: UserCode, Approved, Email, Password → Authenticates user, approves/denies

**Phase 3: Device polls for token**
- POST /token, grant_type=urn:ietf:params:oauth:grant-type:device_code
- Returns authorization_pending (400) while waiting
- Returns slow_down (400) if polling too fast
- Returns access_denied if user denied
- Returns token response when approved

## 5. Implicit Flow (deprecated)
- Triggered when response_type=token in /authorize flow
- Returns access_token directly in AuthorizeConsentResponse
- No refresh token, no authorization code
- Handled via completeImplicit() internal method

## Token Issuance Details
- Access tokens: opaque (32 random bytes, base64url), stored as SHA-256 hash
- Refresh tokens: opaque, same pattern, stored as SHA-256 hash, tracked by FamilyID
- ID tokens: JWT RS256, includes sub, iss, aud, exp, iat, auth_time, nonce, at_hash, user claims per scope
- at_hash: SHA-256 of access_token, left half (16 bytes), base64url encoded

## Token Introspection (POST /introspect, RFC 7662)
- Input: token, token_type_hint (access_token/refresh_token)
- Returns: active, scope, client_id, username, token_type, exp, iat, sub, iss
- Tries hint type first, falls back to other

## Token Revocation (POST /revoke, RFC 7009)
- Input: token, token_type_hint
- Refresh token revocation: revokes entire family + cascades to access tokens
- Access token revocation: revokes single token
- Always returns success (per RFC 7009)

## Security Features
- PKCE S256 required for public clients
- Authorization code replay detection → revokes all session tokens
- Refresh token rotation with family-based reuse detection
- Consent caching (skip if already granted same scopes)
- MFA integration in authorization flow
- First-party client auto-consent
- ID token validation for prompt=none and end_session flows

## OIDC Core Parameters (in /authorize)
- **prompt**: none (silent auth via id_token_hint), login (force re-auth), consent (force consent even for first-party), select_account (returns error)
- **max_age**: stored on auth request, auth_time propagated to ID token
- **display**: page/popup/touch/wap, passed to frontend
- **login_hint**: pre-populates email in AuthUI login form
- **claims**: JSON claims request parameter, honored in ID token generation
- **id_token_hint**: validated via ValidateIDToken, used for prompt=none
- **ui_locales, claims_locales, acr_values**: accepted without error (stored)

## RP-Initiated Logout (GET /end_session)
- Parameters: id_token_hint, post_logout_redirect_uri, state, client_id
- Validates id_token_hint, revokes all user sessions
- Validates post_logout_redirect_uri against client's PostLogoutRedirectURIs
- Returns redirect_uri with state if valid, otherwise shows logout confirmation
