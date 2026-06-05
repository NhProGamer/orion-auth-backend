package email

import (
	"bytes"
	"fmt"

	"orion-auth-backend/model"
)

// OutboxSender implements Sender by rendering the email body and
// enqueueing a row in outbound_emails. The actual SMTP DialAndSend
// happens later in the worker, which gives us retry semantics on
// transient SMTP failures. From the call site's perspective the
// behaviour is identical: Send* returns nil iff the message was
// safely persisted for delivery.
type OutboxSender struct {
	repo   OutboxRepository
	issuer string
}

// NewOutboxSender wraps a repository with the rendering glue. It
// satisfies the Sender interface so existing call sites swap from
// SMTPSender to OutboxSender without code changes.
func NewOutboxSender(repo OutboxRepository, issuer string) *OutboxSender {
	return &OutboxSender{repo: repo, issuer: issuer}
}

func (s *OutboxSender) enqueueRendered(to, subject, templateName string, data EmailData) error {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, templateName, data); err != nil {
		return fmt.Errorf("render %s: %w", templateName, err)
	}
	return s.repo.Enqueue(&model.OutboundEmail{
		Recipient: to,
		Subject:   subject,
		BodyHTML:  buf.String(),
	})
}

func (s *OutboxSender) SendVerificationEmail(to, token string) error {
	return s.enqueueRendered(to, "Verify your email address", "verification.gohtml",
		EmailData{Issuer: s.issuer, Token: token})
}

func (s *OutboxSender) SendPasswordResetEmail(to, token string) error {
	return s.enqueueRendered(to, "Reset your password", "password_reset.gohtml",
		EmailData{Issuer: s.issuer, Token: token})
}

func (s *OutboxSender) SendInvitationEmail(to, token string) error {
	return s.enqueueRendered(to, "You've been invited", "invitation.gohtml",
		EmailData{Issuer: s.issuer, Token: token})
}

func (s *OutboxSender) SendEmailChangeConfirmation(to, token string) error {
	return s.enqueueRendered(to, "Confirm your new email address", "account_email_change.gohtml",
		EmailData{Issuer: s.issuer, Token: token})
}

func (s *OutboxSender) SendEmailChangedNotice(oldEmail, newEmail string) error {
	return s.enqueueRendered(oldEmail, "Your email address was changed", "account_email_changed.gohtml",
		EmailData{Issuer: s.issuer, NewEmail: newEmail})
}

func (s *OutboxSender) SendPasswordChangedNotice(to string) error {
	return s.enqueueRendered(to, "Your password was changed", "account_password_changed.gohtml",
		EmailData{Issuer: s.issuer})
}

func (s *OutboxSender) SendAccountDeletionEmail(to, cancelToken string) error {
	return s.enqueueRendered(to, "Account deletion scheduled", "account_deletion.gohtml",
		EmailData{Issuer: s.issuer, Token: cancelToken})
}
