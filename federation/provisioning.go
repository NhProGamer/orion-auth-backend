package federation

import (
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
	"orion-auth-backend/user"
)

const (
	pendingLinkTTL   = 5 * time.Minute
	pendingSignupTTL = 15 * time.Minute
)

// ProvisionOutcome describes what happened during findOrProvisionUser.
type ProvisionKind int

const (
	// ProvisionLoginExisting indicates an existing FederationLink matched and
	// the user can be logged in directly.
	ProvisionLoginExisting ProvisionKind = iota
	// ProvisionPendingSignup indicates the federated identity does not match
	// any local account and the policy allows signup (registration_enabled
	// or a valid invitation). A pending_signup_token has been staged; the
	// caller must redirect the AuthUI to /complete-account?token=... where
	// the user picks a local password. The actual User and FederationLink
	// rows are only created in CompleteSignup, so abandoning the flow
	// leaves no orphan account behind.
	ProvisionPendingSignup
	// ProvisionPendingLinkConfirmation indicates an email match was found and
	// a pending_link_token was emitted; the caller must redirect the AuthUI
	// to /link-account?token=... where the user proves possession of the
	// existing local account with their password.
	ProvisionPendingLinkConfirmation
	// ProvisionAuthenticatedLink indicates the auth request was initiated
	// by an already-authenticated user (BeginLink) and the federation_link
	// has been created for that user. No login or session is started.
	ProvisionAuthenticatedLink
)

// ProvisionOutcome bundles the result of the provisioning step.
type ProvisionOutcome struct {
	Kind               ProvisionKind
	User               *model.User           // set only for LoginExisting
	PendingLinkToken   string                // set for PendingLinkConfirmation (raw, return to AuthUI)
	PendingSignupToken string                // set for PendingSignup (raw, return to AuthUI)
	Link               *model.FederationLink // set for AuthenticatedLink
}

// ErrAccountExistsLinkRequired is returned when an email collision happens
// but link-confirmation is disabled on the provider (or the existing user
// has no local password to confirm with). The AuthUI should send the user
// to the login page with a clear message.
var ErrAccountExistsLinkRequired = pkg.ErrBadRequest("account exists; sign in with your existing method and link from /me/linked-accounts")

// ErrRegistrationDisabled is returned when the email is unknown but neither
// public registration is enabled nor a valid invitation was attached.
var ErrRegistrationDisabled = pkg.ErrBadRequest("public registration is disabled; an invitation is required")

// ErrIdentityLinkedToOtherUser is returned during BeginLink callback when
// the federation identity returned by the provider is already linked to a
// different local user. Reusing the same external identity across two
// accounts would let an attacker hijack a session.
var ErrIdentityLinkedToOtherUser = pkg.ErrConflict("this provider identity is already linked to another account")

// FindOrProvisionUser is the policy engine of the federation callback. It
// decides whether to log in an existing user, provision a new one, or
// stage a pending link confirmation. The caller (Phase 7) consumes the
// outcome to create a session and continue the flow.
func (s *Service) FindOrProvisionUser(ctx *CallbackContext) (*ProvisionOutcome, error) {
	if s.users == nil {
		return nil, pkg.ErrInternal("federation provisioning dependencies are not wired")
	}
	provider := ctx.Provider
	claims := ctx.Claims
	authReq := ctx.AuthRequest

	if claims.ExternalID == "" {
		return nil, pkg.ErrBadRequest("federation provider returned no subject identifier")
	}

	// 0. Authenticated link flow short-circuit. When the auth request was
	// initiated by an already-logged-in user via BeginLink, we either
	// idempotently return the existing link for that user, refuse if the
	// identity is bound to a different account, or create the link fresh.
	if authReq.LinkUserID != nil {
		return s.completeAuthenticatedLink(*authReq.LinkUserID, provider, claims)
	}

	// 1. Existing link → straight login.
	link, err := s.repo.FindLink(provider.ID, claims.ExternalID)
	if err != nil {
		return nil, pkg.ErrInternal("failed to look up federation link")
	}
	if link != nil {
		u, err := s.users.GetByID(link.UserID)
		if err != nil {
			return nil, pkg.ErrInternal("failed to load linked user")
		}
		if u == nil {
			// Stale link; delete and fall through to provisioning path.
			_ = s.repo.DeleteLink(link.ID)
		} else {
			return &ProvisionOutcome{Kind: ProvisionLoginExisting, User: u}, nil
		}
	}

	// Without an email we cannot do anything else safely.
	if claims.Email == "" {
		return nil, pkg.ErrBadRequest("federation provider returned no email; cannot provision or link account")
	}
	normEmail := strings.ToLower(strings.TrimSpace(claims.Email))

	existing, err := s.users.FindByEmail(normEmail)
	if err != nil {
		return nil, pkg.ErrInternal("failed to look up user by email")
	}

	// 2. Email matches an existing local user → never auto-link.
	if existing != nil {
		if !provider.AllowLinkConfirmation || existing.PasswordHash == nil {
			return nil, ErrAccountExistsLinkRequired
		}
		token, err := s.stagePendingLink(existing, provider, claims, authReq)
		if err != nil {
			return nil, err
		}
		return &ProvisionOutcome{
			Kind:             ProvisionPendingLinkConfirmation,
			PendingLinkToken: token,
		}, nil
	}

	// 3. Unknown email — gate signup on registration_enabled or invitation,
	// then stage the pending signup so the user picks a local password
	// before any DB row is created. Invitation tokens are NOT consumed
	// here; CompleteSignup consumes them only on successful provisioning,
	// so abandoned flows never burn an invite.
	if err := s.checkSignupAllowed(authReq); err != nil {
		return nil, err
	}

	token, err := s.stagePendingSignup(provider, claims, normEmail, authReq)
	if err != nil {
		return nil, err
	}
	slog.Info("federation signup staged", "provider", provider.Name, "email", normEmail)
	return &ProvisionOutcome{Kind: ProvisionPendingSignup, PendingSignupToken: token}, nil
}

// checkSignupAllowed enforces the registration policy without consuming an
// invitation. CompleteSignup re-validates and consumes on success.
func (s *Service) checkSignupAllowed(authReq *model.FederationAuthRequest) error {
	if authReq.InvitationToken != nil && *authReq.InvitationToken != "" && s.invitations != nil {
		inv, err := s.invitations.ValidateToken(*authReq.InvitationToken)
		if err != nil {
			return err
		}
		if inv != nil {
			return nil
		}
	}
	if s.registration == nil || !s.registration.IsRegistrationEnabled() {
		return ErrRegistrationDisabled
	}
	return nil
}

// stagePendingSignup persists the validated claims under a one-shot token.
func (s *Service) stagePendingSignup(provider *model.FederationProvider, claims ProviderClaims, normEmail string, authReq *model.FederationAuthRequest) (string, error) {
	rawToken, err := crypto.GenerateRandomString(32)
	if err != nil {
		return "", pkg.ErrInternal("failed to generate pending-signup token")
	}
	rawBytes, err := json.Marshal(claims.Raw)
	if err != nil {
		return "", pkg.ErrInternal("failed to marshal raw claims")
	}
	pending := &model.FederationPendingSignup{
		TokenHash:       crypto.HashToken(rawToken),
		ProviderID:      provider.ID,
		ExternalID:      claims.ExternalID,
		Email:           normEmail,
		EmailVerified:   claims.EmailVerified,
		DisplayName:     nullableString(claims.Name),
		AvatarURL:       nullableString(claims.Picture),
		RawClaims:       rawBytes,
		OAuthRequestID:  authReq.OAuthRequestID,
		ReturnTo:        authReq.ReturnTo,
		InvitationToken: authReq.InvitationToken,
		IPAddress:       authReq.IPAddress,
		UserAgent:       authReq.UserAgent,
		ExpiresAt:       time.Now().Add(pendingSignupTTL),
	}
	if err := s.stateRepo.InsertPendingSignup(pending); err != nil {
		return "", pkg.ErrInternal("failed to persist pending signup")
	}
	return rawToken, nil
}

// stagePendingLink generates a one-shot opaque token, hashes it (SHA-256)
// for storage, and persists the pending link so the AuthUI can call
// ConfirmLink with the raw token.
func (s *Service) stagePendingLink(existing *model.User, provider *model.FederationProvider, claims ProviderClaims, authReq *model.FederationAuthRequest) (string, error) {
	if s.stateRepo == nil {
		return "", pkg.ErrInternal("federation state store is not configured")
	}
	rawToken, err := crypto.GenerateRandomString(32)
	if err != nil {
		return "", pkg.ErrInternal("failed to generate pending-link token")
	}
	rawBytes, err := json.Marshal(claims.Raw)
	if err != nil {
		return "", pkg.ErrInternal("failed to marshal raw claims")
	}
	emailPtr := nullableString(claims.Email)
	pending := &model.FederationPendingLink{
		TokenHash:      crypto.HashToken(rawToken),
		UserID:         existing.ID,
		ProviderID:     provider.ID,
		ExternalID:     claims.ExternalID,
		Email:          emailPtr,
		RawClaims:      rawBytes,
		OAuthRequestID: authReq.OAuthRequestID,
		ReturnTo:       authReq.ReturnTo,
		IPAddress:      authReq.IPAddress,
		UserAgent:      authReq.UserAgent,
		ExpiresAt:      time.Now().Add(pendingLinkTTL),
	}
	if err := s.stateRepo.InsertPendingLink(pending); err != nil {
		return "", pkg.ErrInternal("failed to persist pending link")
	}
	return rawToken, nil
}

// createLink is the shared helper that turns a successful claim into a
// persistent FederationLink row.
func (s *Service) createLink(userID uuid.UUID, provider *model.FederationProvider, claims ProviderClaims) (*model.FederationLink, error) {
	emailPtr := nullableString(claims.Email)
	rawBytes, err := json.Marshal(claims.Raw)
	if err != nil {
		return nil, pkg.ErrInternal("failed to marshal raw claims")
	}
	link := &model.FederationLink{
		UserID:     userID,
		ProviderID: provider.ID,
		ExternalID: claims.ExternalID,
		Email:      emailPtr,
		Metadata:   rawBytes,
	}
	if err := s.repo.CreateLink(link); err != nil {
		return nil, pkg.ErrInternal("failed to create federation link")
	}
	return link, nil
}

// completeAuthenticatedLink is the BeginLink callback handler. It enforces:
//
//   - the auth user still exists,
//   - the returned external identity is not already attached to a different
//     local user (would let an attacker hijack identities),
//   - idempotency: if the auth user already has this exact link, the
//     existing row is returned without error.
//
// On success a fresh federation_link is persisted bound to the auth user.
func (s *Service) completeAuthenticatedLink(userID uuid.UUID, provider *model.FederationProvider, claims ProviderClaims) (*ProvisionOutcome, error) {
	u, err := s.users.GetByID(userID)
	if err != nil {
		return nil, pkg.ErrInternal("failed to load user for link")
	}
	if u == nil {
		return nil, pkg.ErrBadRequest("the user that initiated the link no longer exists")
	}

	existing, err := s.repo.FindLink(provider.ID, claims.ExternalID)
	if err != nil {
		return nil, pkg.ErrInternal("failed to look up federation link")
	}
	if existing != nil {
		if existing.UserID != userID {
			return nil, ErrIdentityLinkedToOtherUser
		}
		return &ProvisionOutcome{Kind: ProvisionAuthenticatedLink, User: u, Link: existing}, nil
	}

	link, err := s.createLink(userID, provider, claims)
	if err != nil {
		return nil, err
	}
	return &ProvisionOutcome{Kind: ProvisionAuthenticatedLink, User: u, Link: link}, nil
}

// ConfirmLinkResult is what ConfirmLink hands back to the handler so it
// can create a session and resume continuation context (oauth_request_id,
// return_to).
type ConfirmLinkResult struct {
	User           *model.User
	OAuthRequestID *uuid.UUID
	ReturnTo       *string
}

// ConfirmLink completes a pending link confirmation. The user must provide
// the correct local password for the matched account. On success the
// FederationLink row is created and the caller logs the user in.
func (s *Service) ConfirmLink(rawToken, password string) (*ConfirmLinkResult, error) {
	if rawToken == "" || password == "" {
		return nil, pkg.ErrBadRequest("token and password are required")
	}
	if s.users == nil || s.stateRepo == nil {
		return nil, pkg.ErrInternal("federation dependencies are not wired")
	}

	pending, err := s.stateRepo.ConsumePendingLink(crypto.HashToken(rawToken))
	if err != nil {
		return nil, pkg.ErrInternal("failed to consume pending link")
	}
	if pending == nil {
		return nil, pkg.ErrBadRequest("invalid or expired pending link token")
	}

	ok, err := s.users.VerifyPassword(pending.UserID, password)
	if err != nil {
		return nil, pkg.ErrInternal("failed to verify password")
	}
	if !ok {
		return nil, errors.New(invalidPasswordSentinel)
	}

	provider, err := s.repo.FindProviderByID(pending.ProviderID)
	if err != nil || provider == nil {
		return nil, pkg.ErrInternal("pending link references unknown provider")
	}

	emailPtr := pending.Email
	link := &model.FederationLink{
		UserID:     pending.UserID,
		ProviderID: pending.ProviderID,
		ExternalID: pending.ExternalID,
		Email:      emailPtr,
		Metadata:   pending.RawClaims,
	}
	if err := s.repo.CreateLink(link); err != nil {
		return nil, pkg.ErrInternal("failed to create federation link")
	}

	u, err := s.users.GetByID(pending.UserID)
	if err != nil || u == nil {
		return nil, pkg.ErrInternal("failed to load confirmed user")
	}

	slog.Info("federation link confirmed", "user_id", u.ID, "provider", provider.Name)
	return &ConfirmLinkResult{
		User:           u,
		OAuthRequestID: pending.OAuthRequestID,
		ReturnTo:       pending.ReturnTo,
	}, nil
}

// CompleteSignupInput carries the data the AuthUI collects on the
// /complete-account form: the staging token and the password the user
// chose. DisplayName lets the user override the value carried by the
// provider claim if desired.
type CompleteSignupInput struct {
	Token       string
	Password    string
	DisplayName string
	ExtraFields map[string]any
}

// CompleteSignupResult is what CompleteSignup hands back to the handler
// so it can create a session and resume continuation context.
type CompleteSignupResult struct {
	User           *model.User
	OAuthRequestID *uuid.UUID
	ReturnTo       *string
}

// CompleteSignup consumes a pending signup token, finalises the User row
// (with the chosen password set, MustSetPassword=false), creates the
// FederationLink, and consumes the invitation if one was attached.
func (s *Service) CompleteSignup(in CompleteSignupInput) (*CompleteSignupResult, error) {
	if in.Token == "" || in.Password == "" {
		return nil, pkg.ErrBadRequest("token and password are required")
	}
	if s.users == nil || s.stateRepo == nil {
		return nil, pkg.ErrInternal("federation dependencies are not wired")
	}

	pending, err := s.stateRepo.ConsumePendingSignup(crypto.HashToken(in.Token))
	if err != nil {
		return nil, pkg.ErrInternal("failed to consume pending signup")
	}
	if pending == nil {
		return nil, pkg.ErrBadRequest("invalid or expired signup token")
	}

	provider, err := s.repo.FindProviderByID(pending.ProviderID)
	if err != nil || provider == nil {
		return nil, pkg.ErrInternal("pending signup references unknown provider")
	}

	// Re-validate the signup gate: either the registration toggle is
	// still on, or the original invitation token is still valid. This
	// closes the race where an admin disables signup mid-flow.
	var invitation *model.Invitation
	if pending.InvitationToken != nil && *pending.InvitationToken != "" && s.invitations != nil {
		invitation, err = s.invitations.ValidateToken(*pending.InvitationToken)
		if err != nil {
			return nil, err
		}
	}
	if invitation == nil {
		if s.registration == nil || !s.registration.IsRegistrationEnabled() {
			return nil, ErrRegistrationDisabled
		}
	}

	displayName := in.DisplayName
	if displayName == "" && pending.DisplayName != nil {
		displayName = *pending.DisplayName
	}
	avatar := ""
	if pending.AvatarURL != nil {
		avatar = *pending.AvatarURL
	}

	roleIDs := []uuid.UUID(nil)
	if invitation != nil {
		for _, raw := range invitation.RoleIDs {
			if id, e := uuid.Parse(raw); e == nil {
				roleIDs = append(roleIDs, id)
			}
		}
	}

	newUser, err := s.users.CreateFromFederation(user.FederationProvisionInput{
		Email:         pending.Email,
		EmailVerified: pending.EmailVerified,
		DisplayName:   displayName,
		AvatarURL:     avatar,
		Password:      in.Password,
		ExtraFields:   in.ExtraFields,
	}, roleIDs)
	if err != nil {
		return nil, err
	}

	// At this point the user exists in DB. Link creation failure leaves
	// an orphan user, which is acceptable (and recoverable: the user can
	// log in locally and re-attempt federation linking from /me).
	claimsForLink := ProviderClaims{
		ExternalID: pending.ExternalID,
		Email:      pending.Email,
		Raw:        decodeRawClaims(pending.RawClaims),
	}
	if _, err := s.createLink(newUser.ID, provider, claimsForLink); err != nil {
		slog.Warn("federation link creation failed after signup", "user_id", newUser.ID, "error", err)
	}

	if invitation != nil && s.invitations != nil {
		if err := s.invitations.ConsumeToken(invitation); err != nil {
			slog.Warn("failed to consume invitation after federation signup", "error", err)
		}
	}

	slog.Info("federation signup completed", "user_id", newUser.ID, "provider", provider.Name)
	return &CompleteSignupResult{
		User:           newUser,
		OAuthRequestID: pending.OAuthRequestID,
		ReturnTo:       pending.ReturnTo,
	}, nil
}

// PendingSignupView is the read-only projection used by the AuthUI to
// render the /complete-account form (email + display name suggestion,
// provider label). It deliberately omits the raw claims and the
// invitation token.
type PendingSignupView struct {
	ProviderName        string
	ProviderDisplayName string
	Email               string
	EmailVerified       bool
	DisplayName         string
	ExpiresAt           time.Time
}

// PeekPendingSignup returns the read-only projection of a staged signup
// for the AuthUI's onboarding form, without consuming the token.
func (s *Service) PeekPendingSignup(rawToken string) (*PendingSignupView, error) {
	if rawToken == "" {
		return nil, pkg.ErrBadRequest("token is required")
	}
	if s.stateRepo == nil {
		return nil, pkg.ErrInternal("federation state store is not configured")
	}
	pending, err := s.stateRepo.GetPendingSignup(crypto.HashToken(rawToken))
	if err != nil {
		return nil, pkg.ErrInternal("failed to load pending signup")
	}
	if pending == nil {
		return nil, pkg.ErrBadRequest("invalid or expired signup token")
	}
	provider, err := s.repo.FindProviderByID(pending.ProviderID)
	if err != nil || provider == nil {
		return nil, pkg.ErrInternal("pending signup references unknown provider")
	}
	displayName := ""
	if pending.DisplayName != nil {
		displayName = *pending.DisplayName
	}
	providerDisplay := provider.Name
	if provider.DisplayName != nil && *provider.DisplayName != "" {
		providerDisplay = *provider.DisplayName
	}
	return &PendingSignupView{
		ProviderName:        provider.Name,
		ProviderDisplayName: providerDisplay,
		Email:               pending.Email,
		EmailVerified:       pending.EmailVerified,
		DisplayName:         displayName,
		ExpiresAt:           pending.ExpiresAt,
	}, nil
}

// decodeRawClaims safely unmarshals the JSONB claims blob back into a map.
// Returns an empty map on any error so callers can keep going.
func decodeRawClaims(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{}
	}
	return out
}

// invalidPasswordSentinel is exported indirectly via IsInvalidConfirmPassword
// so the handler can produce a 401 without leaking which side failed.
const invalidPasswordSentinel = "federation: invalid password for pending link confirmation"

// IsInvalidConfirmPassword reports whether an error returned by ConfirmLink
// is the "wrong password" case (vs internal/persistence failures).
func IsInvalidConfirmPassword(err error) bool {
	return err != nil && err.Error() == invalidPasswordSentinel
}
