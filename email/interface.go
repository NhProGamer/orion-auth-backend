package email

import "gorm.io/gorm"

// Sender is the basic email-sending surface used by code that doesn't
// need to coordinate the enqueue with a wider database transaction.
// Implementations: SMTPSender (direct delivery), OutboxSender (queued
// delivery via the outbound_emails table).
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

// TxSender extends Sender with InTx variants that take an open *gorm.DB
// transaction. Only OutboxSender satisfies this — SMTPSender has nothing
// to do with the database, so giving it InTx methods would be a lie.
// Services that need atomicity between the domain write and the email
// enqueue depend on TxSender; everyone else stays on Sender.
type TxSender interface {
	Sender

	SendVerificationEmailInTx(tx *gorm.DB, to, token string) error
	SendPasswordResetEmailInTx(tx *gorm.DB, to, token string) error
	SendInvitationEmailInTx(tx *gorm.DB, to, token string) error
	SendEmailChangeConfirmationInTx(tx *gorm.DB, to, token string) error
	SendEmailChangedNoticeInTx(tx *gorm.DB, oldEmail, newEmail string) error
	SendPasswordChangedNoticeInTx(tx *gorm.DB, to string) error
	SendAccountDeletionEmailInTx(tx *gorm.DB, to, cancelToken string) error
}
