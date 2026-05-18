package passkey

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"orion-auth-backend/model"
)

// webauthnUser adapts model.User + its passkeys to the webauthn.User interface.
type webauthnUser struct {
	user     *model.User
	passkeys []model.Passkey
}

func newWebAuthnUser(u *model.User, passkeys []model.Passkey) *webauthnUser {
	return &webauthnUser{user: u, passkeys: passkeys}
}

// WebAuthnID returns the user handle — the user's UUID v7 byte-encoded.
// UUID v7 is 16 bytes, well under the 64-byte limit.
func (w *webauthnUser) WebAuthnID() []byte {
	id := w.user.ID
	return id[:]
}

func (w *webauthnUser) WebAuthnName() string {
	return w.user.Email
}

func (w *webauthnUser) WebAuthnDisplayName() string {
	if w.user.DisplayName != nil && *w.user.DisplayName != "" {
		return *w.user.DisplayName
	}
	return w.user.Email
}

func (w *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	creds := make([]webauthn.Credential, 0, len(w.passkeys))
	for _, p := range w.passkeys {
		transports := make([]protocol.AuthenticatorTransport, 0, len(p.Transports))
		for _, t := range p.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
		creds = append(creds, webauthn.Credential{
			ID:              p.CredentialID,
			PublicKey:       p.PublicKey,
			AttestationType: p.AttestationType,
			Transport:       transports,
			Flags:           webauthn.NewCredentialFlags(protocol.AuthenticatorFlags(p.Flags)),
			Authenticator: webauthn.Authenticator{
				AAGUID:    p.AAGUID,
				SignCount: p.SignCount,
			},
		})
	}
	return creds
}
