package passkey

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
)

// Challenge purposes stored on PasskeyChallenge.Purpose.
const (
	PurposeRegistration = "registration"
	PurposeLogin        = "login"
	PurposeReauth       = "reauth"
)

type Service struct {
	repo         RepositoryInterface
	userFinder   UserFinder
	wa           *webauthn.WebAuthn
	challengeTTL time.Duration
}

func NewService(repo RepositoryInterface, userFinder UserFinder, wa *webauthn.WebAuthn, challengeTTL time.Duration) *Service {
	return &Service{
		repo:         repo,
		userFinder:   userFinder,
		wa:           wa,
		challengeTTL: challengeTTL,
	}
}

// BeginRegistration starts an enrollment ceremony for an authenticated user.
// Returns the CredentialCreation payload to forward to the browser and a
// challenge ID the client must echo back on FinishRegistration.
type BeginRegistrationResponse struct {
	ChallengeID uuid.UUID                    `json:"challenge_id"`
	Options     *protocol.CredentialCreation `json:"options"`
}

func (s *Service) BeginRegistration(userID uuid.UUID) (*BeginRegistrationResponse, error) {
	u, err := s.userFinder.GetByID(userID)
	if err != nil {
		return nil, err
	}

	existing, err := s.repo.ListByUser(userID)
	if err != nil {
		return nil, pkg.ErrInternal("failed to list existing passkeys")
	}

	wu := newWebAuthnUser(u, existing)

	exclusions := make([]protocol.CredentialDescriptor, 0, len(existing))
	for _, p := range existing {
		exclusions = append(exclusions, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: p.CredentialID,
		})
	}

	creation, sessionData, err := s.wa.BeginRegistration(wu, webauthn.WithExclusions(exclusions))
	if err != nil {
		slog.Warn("BeginRegistration failed", "error", err)
		return nil, pkg.ErrBadRequest("failed to start passkey registration: " + err.Error())
	}

	challengeID, err := s.storeChallenge(&userID, PurposeRegistration, sessionData)
	if err != nil {
		return nil, err
	}

	return &BeginRegistrationResponse{ChallengeID: challengeID, Options: creation}, nil
}

// FinishRegistration validates the authenticator response and persists the
// passkey for the user.
type FinishRegistrationInput struct {
	ChallengeID uuid.UUID `json:"challenge_id" binding:"required"`
	Name        string    `json:"name"`
	Response    []byte    `json:"response" binding:"required"` // raw PublicKeyCredential JSON
}

func (s *Service) FinishRegistration(userID uuid.UUID, input FinishRegistrationInput) (*model.Passkey, error) {
	sessionData, err := s.popChallenge(input.ChallengeID, &userID, PurposeRegistration)
	if err != nil {
		return nil, err
	}

	u, err := s.userFinder.GetByID(userID)
	if err != nil {
		return nil, err
	}
	existing, err := s.repo.ListByUser(userID)
	if err != nil {
		return nil, pkg.ErrInternal("failed to list existing passkeys")
	}
	wu := newWebAuthnUser(u, existing)

	req := buildRequest(input.Response)
	credential, err := s.wa.FinishRegistration(wu, *sessionData, req)
	if err != nil {
		slog.Warn("FinishRegistration failed", "error", err, "user_id", userID)
		return nil, pkg.ErrBadRequest("passkey registration failed: " + err.Error())
	}

	name := input.Name
	if name == "" {
		name = fmt.Sprintf("Passkey %s", time.Now().Format("2006-01-02"))
	}

	transports := make([]string, 0, len(credential.Transport))
	for _, t := range credential.Transport {
		transports = append(transports, string(t))
	}

	p := &model.Passkey{
		UserID:          userID,
		CredentialID:    credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		AAGUID:          credential.Authenticator.AAGUID,
		SignCount:       credential.Authenticator.SignCount,
		Transports:      pq.StringArray(transports),
		Flags:           uint8(credential.Flags.ProtocolValue()),
		Name:            name,
	}
	if err := s.repo.Create(p); err != nil {
		slog.Error("failed to persist passkey", "error", err)
		return nil, pkg.ErrInternal("failed to save passkey")
	}

	slog.Info("passkey registered", "user_id", userID, "passkey_id", p.ID, "name", p.Name)
	return p, nil
}

// BeginLogin starts a usernameless (discoverable credential) login ceremony.
type BeginLoginResponse struct {
	ChallengeID uuid.UUID                     `json:"challenge_id"`
	Options     *protocol.CredentialAssertion `json:"options"`
}

func (s *Service) BeginLogin() (*BeginLoginResponse, error) {
	assertion, sessionData, err := s.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, pkg.ErrInternal("failed to start passkey login: " + err.Error())
	}
	challengeID, err := s.storeChallenge(nil, PurposeLogin, sessionData)
	if err != nil {
		return nil, err
	}
	return &BeginLoginResponse{ChallengeID: challengeID, Options: assertion}, nil
}

// FinishLogin validates a discoverable assertion and returns the matching
// user and passkey. The caller is responsible for issuing a session/token.
type FinishLoginInput struct {
	ChallengeID uuid.UUID `json:"challenge_id" binding:"required"`
	Response    []byte    `json:"response" binding:"required"`
}

func (s *Service) FinishLogin(input FinishLoginInput) (*model.User, *model.Passkey, error) {
	sessionData, err := s.popChallenge(input.ChallengeID, nil, PurposeLogin)
	if err != nil {
		return nil, nil, err
	}

	var matchedUser *model.User
	var matchedPasskey *model.Passkey

	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		userID, parseErr := uuid.FromBytes(userHandle)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid user handle: %w", parseErr)
		}
		u, fErr := s.userFinder.GetByID(userID)
		if fErr != nil {
			return nil, fErr
		}
		passkeys, lErr := s.repo.ListByUser(userID)
		if lErr != nil {
			return nil, lErr
		}
		matchedUser = u
		for i := range passkeys {
			if bytes.Equal(passkeys[i].CredentialID, rawID) {
				matchedPasskey = &passkeys[i]
				break
			}
		}
		return newWebAuthnUser(u, passkeys), nil
	}

	req := buildRequest(input.Response)
	credential, err := s.wa.FinishDiscoverableLogin(handler, *sessionData, req)
	if err != nil {
		slog.Warn("FinishDiscoverableLogin failed", "error", err)
		return nil, nil, pkg.ErrUnauthorized("invalid passkey assertion: " + err.Error())
	}

	if matchedPasskey != nil {
		// CloneWarning from go-webauthn means the authenticator's
		// signCount went backwards or stalled — a strong indicator the
		// credential has been cloned. Flag it and refuse the login
		// rather than silently writing the lower count back over the
		// legitimate one (Vuln 7).
		if credential.Authenticator.CloneWarning {
			_ = s.repo.SetCloneWarning(matchedPasskey.ID, true)
			slog.Warn("passkey clone warning detected (login)",
				"user_id", matchedPasskey.UserID, "passkey_id", matchedPasskey.ID)
			return nil, nil, pkg.ErrUnauthorized("passkey verification failed; please re-enroll your passkey")
		}
		_ = s.repo.UpdateSignCount(matchedPasskey.ID, credential.Authenticator.SignCount, time.Now().Unix())
	}
	return matchedUser, matchedPasskey, nil
}

// ValidateReauthAssertion validates a passkey assertion for step-up reauth.
// Unlike FinishLogin, this is bound to a known userID — the user must already
// be authenticated via bearer token.
func (s *Service) ValidateReauthAssertion(userID, challengeID uuid.UUID, response []byte) (bool, error) {
	sessionData, err := s.popChallenge(challengeID, &userID, PurposeReauth)
	if err != nil {
		return false, err
	}

	u, err := s.userFinder.GetByID(userID)
	if err != nil {
		return false, err
	}
	passkeys, err := s.repo.ListByUser(userID)
	if err != nil {
		return false, pkg.ErrInternal("failed to list passkeys")
	}
	wu := newWebAuthnUser(u, passkeys)

	req := buildRequest(response)
	credential, err := s.wa.FinishLogin(wu, *sessionData, req)
	if err != nil {
		slog.Warn("passkey reauth FinishLogin failed", "error", err, "user_id", userID)
		return false, nil
	}

	for i := range passkeys {
		if bytes.Equal(passkeys[i].CredentialID, credential.ID) {
			// CloneWarning during reauth is even more suspicious than
			// during login: refuse step-up so an attacker can't escalate
			// using a cloned authenticator (Vuln 7).
			if credential.Authenticator.CloneWarning {
				_ = s.repo.SetCloneWarning(passkeys[i].ID, true)
				slog.Warn("passkey clone warning detected (reauth)",
					"user_id", userID, "passkey_id", passkeys[i].ID)
				return false, pkg.ErrUnauthorized("passkey verification failed; please re-enroll your passkey")
			}
			_ = s.repo.UpdateSignCount(passkeys[i].ID, credential.Authenticator.SignCount, time.Now().Unix())
			break
		}
	}
	return true, nil
}

// BeginReauth starts a reauth assertion ceremony for the currently signed-in user.
func (s *Service) BeginReauth(userID uuid.UUID) (*BeginLoginResponse, error) {
	u, err := s.userFinder.GetByID(userID)
	if err != nil {
		return nil, err
	}
	passkeys, err := s.repo.ListByUser(userID)
	if err != nil {
		return nil, pkg.ErrInternal("failed to list passkeys")
	}
	if len(passkeys) == 0 {
		return nil, pkg.ErrBadRequest("user has no passkeys")
	}
	wu := newWebAuthnUser(u, passkeys)
	assertion, sessionData, err := s.wa.BeginLogin(wu)
	if err != nil {
		return nil, pkg.ErrInternal("failed to start passkey reauth: " + err.Error())
	}
	challengeID, err := s.storeChallenge(&userID, PurposeReauth, sessionData)
	if err != nil {
		return nil, err
	}
	return &BeginLoginResponse{ChallengeID: challengeID, Options: assertion}, nil
}

// HasUserVerifiedPasskey reports whether the user has at least one passkey
// registered as user-verified AND not flagged as cloned. A passkey with
// CloneWarning=true is treated as untrusted MFA material (Vuln 7).
func (s *Service) HasUserVerifiedPasskey(userID uuid.UUID) (bool, error) {
	passkeys, err := s.repo.ListByUser(userID)
	if err != nil {
		return false, err
	}
	for _, p := range passkeys {
		if p.CloneWarning {
			continue
		}
		flags := webauthn.NewCredentialFlags(protocol.AuthenticatorFlags(p.Flags))
		if flags.UserVerified {
			return true, nil
		}
	}
	return false, nil
}

func (s *Service) List(userID uuid.UUID) ([]model.Passkey, error) {
	return s.repo.ListByUser(userID)
}

type RenameInput struct {
	Name string `json:"name" binding:"required,min=1,max=100"`
}

func (s *Service) Rename(passkeyID, userID uuid.UUID, name string) error {
	if err := s.repo.UpdateName(passkeyID, userID, name); err != nil {
		return pkg.ErrNotFound("passkey not found")
	}
	slog.Info("passkey renamed", "user_id", userID, "passkey_id", passkeyID)
	return nil
}

func (s *Service) Delete(passkeyID, userID uuid.UUID) error {
	if err := s.repo.Delete(passkeyID, userID); err != nil {
		return pkg.ErrNotFound("passkey not found")
	}
	slog.Info("passkey removed", "user_id", userID, "passkey_id", passkeyID)
	return nil
}

func (s *Service) CleanupExpiredChallenges() (int64, error) {
	return s.repo.DeleteExpiredChallenges()
}

// --- session data persistence helpers ---

func (s *Service) storeChallenge(userID *uuid.UUID, purpose string, data *webauthn.SessionData) (uuid.UUID, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(data); err != nil {
		return uuid.Nil, pkg.ErrInternal("failed to encode session data")
	}
	id, _ := uuid.NewV7()
	c := &model.PasskeyChallenge{
		ID:          id,
		UserID:      userID,
		Purpose:     purpose,
		SessionData: buf.Bytes(),
		ExpiresAt:   time.Now().Add(s.challengeTTL),
	}
	if err := s.repo.CreateChallenge(c); err != nil {
		return uuid.Nil, pkg.ErrInternal("failed to persist challenge")
	}
	return id, nil
}

// popChallenge fetches and deletes a challenge in one go (single-use).
func (s *Service) popChallenge(id uuid.UUID, expectedUserID *uuid.UUID, expectedPurpose string) (*webauthn.SessionData, error) {
	c, err := s.repo.FindChallenge(id)
	if err != nil {
		return nil, pkg.ErrInternal("failed to fetch challenge")
	}
	if c == nil {
		return nil, pkg.ErrBadRequest("invalid challenge")
	}
	defer func() { _ = s.repo.DeleteChallenge(id) }()

	if c.IsExpired() {
		return nil, pkg.ErrBadRequest("challenge expired")
	}
	if c.Purpose != expectedPurpose {
		return nil, pkg.ErrBadRequest("challenge purpose mismatch")
	}
	if expectedUserID != nil {
		if c.UserID == nil || *c.UserID != *expectedUserID {
			return nil, pkg.ErrBadRequest("challenge does not belong to user")
		}
	}

	var data webauthn.SessionData
	if err := gob.NewDecoder(bytes.NewReader(c.SessionData)).Decode(&data); err != nil {
		return nil, pkg.ErrInternal("failed to decode session data")
	}
	return &data, nil
}

// buildRequest wraps the raw assertion/attestation JSON in a *http.Request so
// we can call the go-webauthn Finish* helpers which expect that shape.
func buildRequest(rawResponse []byte) *http.Request {
	return &http.Request{
		Body: io.NopCloser(bytes.NewReader(rawResponse)),
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}
}
