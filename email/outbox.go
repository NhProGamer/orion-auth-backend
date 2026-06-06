package email

import (
	"fmt"

	"gorm.io/gorm"

	"orion-auth-backend/model"
)

// OutboxSender implements Sender by rendering the email body and
// enqueueing a row in outbound_emails. The actual SMTP DialAndSend
// happens later in the worker, which gives us retry semantics on
// transient SMTP failures. From the call site's perspective the
// behaviour is identical: Send* returns nil iff the message was
// safely persisted for delivery.
//
// OutboxSender also satisfies TxSender, exposing *InTx variants that
// enqueue the row within a caller-managed *gorm.DB transaction. Used by
// services that need user-row INSERT + email enqueue to commit or roll
// back together.
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

func (s *OutboxSender) render(templateName string, data EmailData) (subject, body string, err error) {
	subject, body, err = s.resolver.Render(templateName, data)
	if err != nil {
		return "", "", fmt.Errorf("render %s: %w", templateName, err)
	}
	return subject, body, nil
}

func (s *OutboxSender) enqueueRendered(to, templateName string, data EmailData) error {
	subject, body, err := s.render(templateName, data)
	if err != nil {
		return err
	}
	return s.repo.Enqueue(&model.OutboundEmail{
		Recipient: to,
		Subject:   subject,
		BodyHTML:  body,
	})
}

func (s *OutboxSender) enqueueRenderedInTx(tx *gorm.DB, to, templateName string, data EmailData) error {
	subject, body, err := s.render(templateName, data)
	if err != nil {
		return err
	}
	return s.repo.EnqueueInTx(tx, &model.OutboundEmail{
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

// --- TxSender variants -----------------------------------------------------

func (s *OutboxSender) SendVerificationEmailInTx(tx *gorm.DB, to, token string) error {
	return s.enqueueRenderedInTx(tx, to, "verification", EmailData{Issuer: s.issuer, Token: token})
}

func (s *OutboxSender) SendPasswordResetEmailInTx(tx *gorm.DB, to, token string) error {
	return s.enqueueRenderedInTx(tx, to, "password_reset", EmailData{Issuer: s.issuer, Token: token})
}

func (s *OutboxSender) SendInvitationEmailInTx(tx *gorm.DB, to, token string) error {
	return s.enqueueRenderedInTx(tx, to, "invitation", EmailData{Issuer: s.issuer, Token: token})
}

func (s *OutboxSender) SendEmailChangeConfirmationInTx(tx *gorm.DB, to, token string) error {
	return s.enqueueRenderedInTx(tx, to, "account_email_change", EmailData{Issuer: s.issuer, Token: token})
}

func (s *OutboxSender) SendEmailChangedNoticeInTx(tx *gorm.DB, oldEmail, newEmail string) error {
	return s.enqueueRenderedInTx(tx, oldEmail, "account_email_changed", EmailData{Issuer: s.issuer, NewEmail: newEmail})
}

func (s *OutboxSender) SendPasswordChangedNoticeInTx(tx *gorm.DB, to string) error {
	return s.enqueueRenderedInTx(tx, to, "account_password_changed", EmailData{Issuer: s.issuer})
}

func (s *OutboxSender) SendAccountDeletionEmailInTx(tx *gorm.DB, to, cancelToken string) error {
	return s.enqueueRenderedInTx(tx, to, "account_deletion", EmailData{Issuer: s.issuer, Token: cancelToken})
}
