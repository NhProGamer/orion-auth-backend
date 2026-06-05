package email

import (
	"fmt"
	"log/slog"

	"github.com/wneessen/go-mail"

	"orion-auth-backend/config"
)

// EmailData is the payload exposed to templates as the dot value.
// New fields require a matching entry in resolver.variables and an
// AdminUI bump so admins can insert the new placeholder.
type EmailData struct {
	Issuer   string
	Token    string
	NewEmail string
}

type SMTPSender struct {
	cfg      config.SMTPConfig
	issuer   string
	resolver *Resolver
}

func NewSMTPSender(cfg config.SMTPConfig, issuer string, resolver *Resolver) *SMTPSender {
	return &SMTPSender{cfg: cfg, issuer: issuer, resolver: resolver}
}

func (s *SMTPSender) renderAndSend(to, name string, data EmailData) error {
	subject, body, err := s.resolver.Render(name, data)
	if err != nil {
		return fmt.Errorf("render %s: %w", name, err)
	}
	return s.send(to, subject, body)
}

func (s *SMTPSender) SendVerificationEmail(to, token string) error {
	return s.renderAndSend(to, "verification", EmailData{Issuer: s.issuer, Token: token})
}

func (s *SMTPSender) SendPasswordResetEmail(to, token string) error {
	return s.renderAndSend(to, "password_reset", EmailData{Issuer: s.issuer, Token: token})
}

func (s *SMTPSender) SendInvitationEmail(to, token string) error {
	return s.renderAndSend(to, "invitation", EmailData{Issuer: s.issuer, Token: token})
}

func (s *SMTPSender) SendEmailChangeConfirmation(to, token string) error {
	return s.renderAndSend(to, "account_email_change", EmailData{Issuer: s.issuer, Token: token})
}

func (s *SMTPSender) SendEmailChangedNotice(oldEmail, newEmail string) error {
	return s.renderAndSend(oldEmail, "account_email_changed", EmailData{Issuer: s.issuer, NewEmail: newEmail})
}

func (s *SMTPSender) SendPasswordChangedNotice(to string) error {
	return s.renderAndSend(to, "account_password_changed", EmailData{Issuer: s.issuer})
}

func (s *SMTPSender) SendAccountDeletionEmail(to, cancelToken string) error {
	return s.renderAndSend(to, "account_deletion", EmailData{Issuer: s.issuer, Token: cancelToken})
}

// Deliver sends an already-rendered HTML body to a recipient. Used by
// the outbox worker; the high-level Send* methods on this type render
// via the resolver and then call this. Exposed so the worker can
// deliver without re-rendering.
func (s *SMTPSender) Deliver(to, subject, htmlBody string) error {
	return s.send(to, subject, htmlBody)
}

func (s *SMTPSender) send(to, subject, htmlBody string) error {
	m := mail.NewMsg()
	if err := m.FromFormat(s.cfg.FromName, s.cfg.From); err != nil {
		return fmt.Errorf("failed to set from: %w", err)
	}
	if err := m.To(to); err != nil {
		return fmt.Errorf("failed to set to: %w", err)
	}
	m.Subject(subject)
	m.SetBodyString(mail.TypeTextHTML, htmlBody)

	opts := []mail.Option{
		mail.WithPort(s.cfg.Port),
	}

	if s.cfg.TLS {
		opts = append(opts, mail.WithTLSPortPolicy(mail.TLSMandatory))
	} else {
		opts = append(opts, mail.WithTLSPortPolicy(mail.NoTLS))
	}

	if s.cfg.Username != "" {
		opts = append(opts,
			mail.WithUsername(s.cfg.Username),
			mail.WithPassword(s.cfg.Password),
			mail.WithSMTPAuth(mail.SMTPAuthPlain),
		)
	}

	c, err := mail.NewClient(s.cfg.Host, opts...)
	if err != nil {
		return fmt.Errorf("failed to create mail client: %w", err)
	}

	if err := c.DialAndSend(m); err != nil {
		slog.Error("failed to send email", "to", to, "subject", subject, "error", err)
		return fmt.Errorf("failed to send email: %w", err)
	}

	slog.Info("email sent", "to", to, "subject", subject)
	return nil
}
