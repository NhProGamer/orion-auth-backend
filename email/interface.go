package email

// Sender defines the interface for sending emails.
type Sender interface {
	SendVerificationEmail(to, token string) error
	SendPasswordResetEmail(to, token string) error
	SendInvitationEmail(to, token string) error
}
