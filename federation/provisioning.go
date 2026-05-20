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

const pendingLinkTTL = 5 * time.Minute

// ProvisionOutcome describes what happened during findOrProvisionUser.
type ProvisionKind int

const (
	// ProvisionLoginExisting indicates an existing FederationLink matched and
	// the user can be logged in directly.
	ProvisionLoginExisting ProvisionKind = iota
	// ProvisionCreated indicates a brand-new user was provisioned from the
	// claims (registration-enabled or invitation-driven path).
	ProvisionCreated
	// ProvisionPendingLinkConfirmation indicates an email match was found and
	// a pending_link_token was emitted; the caller must redirect the AuthUI
	// to /link-account?token=... where the user proves possession of the
	// existing local account with their password.
	ProvisionPendingLinkConfirmation
)

// ProvisionOutcome bundles the result of the provisioning step.
type ProvisionOutcome struct {
	Kind             ProvisionKind
	User             *model.User // set for LoginExisting and Created
	PendingLinkToken string      // set for PendingLinkConfirmation (raw, return to AuthUI)
}

// ErrAccountExistsLinkRequired is returned when an email collision happens
// but link-confirmation is disabled on the provider (or the existing user
// has no local password to confirm with). The AuthUI should send the user
// to the login page with a clear message.
var ErrAccountExistsLinkRequired = pkg.ErrBadRequest("account exists; sign in with your existing method and link from /me/linked-accounts")

// ErrRegistrationDisabled is returned when the email is unknown but neither
// public registration is enabled nor a valid invitation was attached.
var ErrRegistrationDisabled = pkg.ErrBadRequest("public registration is disabled; an invitation is required")

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

	// 3. Unknown email — gate signup on registration_enabled or invitation.
	roleIDs, err := s.resolveSignupGate(authReq)
	if err != nil {
		return nil, err
	}

	newUser, err := s.users.CreateFromFederation(user.FederationProvisionInput{
		Email:         normEmail,
		EmailVerified: claims.EmailVerified,
		DisplayName:   claims.Name,
		AvatarURL:     claims.Picture,
	}, roleIDs)
	if err != nil {
		return nil, err
	}

	if _, err := s.createLink(newUser.ID, provider, claims); err != nil {
		return nil, err
	}

	slog.Info("federation user provisioned + linked", "user_id", newUser.ID, "provider", provider.Name)
	return &ProvisionOutcome{Kind: ProvisionCreated, User: newUser}, nil
}

// resolveSignupGate enforces the registration policy and returns the role
// IDs that should be assigned to the new user (drawn from an invitation
// when one is present).
func (s *Service) resolveSignupGate(authReq *model.FederationAuthRequest) ([]uuid.UUID, error) {
	// Invitation path: validate (without consuming) and use its role set.
	if authReq.InvitationToken != nil && *authReq.InvitationToken != "" && s.invitations != nil {
		inv, err := s.invitations.ValidateToken(*authReq.InvitationToken)
		if err != nil {
			return nil, err
		}
		if inv != nil {
			roleIDs := make([]uuid.UUID, 0, len(inv.RoleIDs))
			for _, raw := range inv.RoleIDs {
				if id, err := uuid.Parse(raw); err == nil {
					roleIDs = append(roleIDs, id)
				}
			}
			// Consume immediately so the same token cannot be reused even
			// if user creation downstream fails — invitations are single-use.
			if err := s.invitations.ConsumeToken(inv); err != nil {
				slog.Warn("failed to consume invitation after federation signup", "error", err)
			}
			return roleIDs, nil
		}
	}

	if s.registration == nil || !s.registration.IsRegistrationEnabled() {
		return nil, ErrRegistrationDisabled
	}
	return nil, nil
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

// invalidPasswordSentinel is exported indirectly via IsInvalidConfirmPassword
// so the handler can produce a 401 without leaking which side failed.
const invalidPasswordSentinel = "federation: invalid password for pending link confirmation"

// IsInvalidConfirmPassword reports whether an error returned by ConfirmLink
// is the "wrong password" case (vs internal/persistence failures).
func IsInvalidConfirmPassword(err error) bool {
	return err != nil && err.Error() == invalidPasswordSentinel
}
