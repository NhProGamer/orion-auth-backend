package email

import (
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
	repo     OutboxRepository
	issuer   string
	resolver *Resolver
}

// NewOutboxSender wraps a repository with the rendering glue. It
// satisfies the Sender interface so existing call sites swap from
// SMTPSender to OutboxSender without code changes.
func NewOutboxSender(repo OutboxRepository, issuer string, resolver *Resolver) *OutboxSender {
	return &OutboxSender{repo: repo, issuer: issuer, resolver: resolver}
}

func (s *OutboxSender) enqueueRendered(to, templateName string, data EmailData) error {
	subject, body, err := s.resolver.Render(templateName, data)
	if err != nil {
		return fmt.Errorf("render %s: %w", templateName, err)
	}
	return s.repo.Enqueue(&model.OutboundEmail{
		Recipient: to,
		Subject:   subject,
		BodyHTML:  body,
	})
}

func (s *OutboxSender) SendVerificationEmail(to, token string) error {
	return s.enqueueRendered(to, "verification", EmailData{Issuer: s.issuer, Token: token})
}

func (s *OutboxSender) SendPasswordResetEmail(to, token string) error {
	return s.enqueueRendered(to, "password_reset", EmailData{Issuer: s.issuer, Token: token})
}

func (s *OutboxSender) SendInvitationEmail(to, token string) error {
	return s.enqueueRendered(to, "invitation", EmailData{Issuer: s.issuer, Token: token})
}

func (s *OutboxSender) SendEmailChangeConfirmation(to, token string) error {
	return s.enqueueRendered(to, "account_email_change", EmailData{Issuer: s.issuer, Token: token})
}

func (s *OutboxSender) SendEmailChangedNotice(oldEmail, newEmail string) error {
	return s.enqueueRendered(oldEmail, "account_email_changed", EmailData{Issuer: s.issuer, NewEmail: newEmail})
}

func (s *OutboxSender) SendPasswordChangedNotice(to string) error {
	return s.enqueueRendered(to, "account_password_changed", EmailData{Issuer: s.issuer})
}

func (s *OutboxSender) SendAccountDeletionEmail(to, cancelToken string) error {
	return s.enqueueRendered(to, "account_deletion", EmailData{Issuer: s.issuer, Token: cancelToken})
}
