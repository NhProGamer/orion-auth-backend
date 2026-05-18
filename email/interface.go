package email

// Sender defines the interface for sending emails.
type Sender interface {
	SendVerificationEmail(to, token string) error
	SendPasswordResetEmail(to, token string) error
	SendInvitationEmail(to, token string) error

	// Account self-service notifications
	SendEmailChangeConfirmation(to, token string) error
	SendEmailChangedNotice(oldEmail, newEmail string) error
	SendPasswordChangedNotice(to string) error
	SendAccountDeletionEmail(to, cancelToken string) error
}
