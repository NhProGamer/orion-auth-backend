package email

import (
	"bytes"
	"fmt"
	"html/template"
	"log/slog"

	"github.com/wneessen/go-mail"

	"orion-auth-backend/config"
	"orion-auth-backend/email/templates"
)

var tmpl = template.Must(template.ParseFS(templates.FS, "*.gohtml"))

type EmailData struct {
	Issuer   string
	Token    string
	NewEmail string
}

type SMTPSender struct {
	cfg    config.SMTPConfig
	issuer string
}

func NewSMTPSender(cfg config.SMTPConfig, issuer string) *SMTPSender {
	return &SMTPSender{cfg: cfg, issuer: issuer}
}

func (s *SMTPSender) SendVerificationEmail(to, token string) error {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "verification.gohtml", EmailData{Issuer: s.issuer, Token: token}); err != nil {
		return fmt.Errorf("failed to render email template: %w", err)
	}
	return s.send(to, "Verify your email address", buf.String())
}

func (s *SMTPSender) SendPasswordResetEmail(to, token string) error {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "password_reset.gohtml", EmailData{Issuer: s.issuer, Token: token}); err != nil {
		return fmt.Errorf("failed to render email template: %w", err)
	}
	return s.send(to, "Reset your password", buf.String())
}

func (s *SMTPSender) SendInvitationEmail(to, token string) error {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "invitation.gohtml", EmailData{Issuer: s.issuer, Token: token}); err != nil {
		return fmt.Errorf("failed to render email template: %w", err)
	}
	return s.send(to, "You've been invited", buf.String())
}

func (s *SMTPSender) SendEmailChangeConfirmation(to, token string) error {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "account_email_change.gohtml", EmailData{Issuer: s.issuer, Token: token}); err != nil {
		return fmt.Errorf("failed to render email template: %w", err)
	}
	return s.send(to, "Confirm your new email address", buf.String())
}

func (s *SMTPSender) SendEmailChangedNotice(oldEmail, newEmail string) error {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "account_email_changed.gohtml", EmailData{Issuer: s.issuer, NewEmail: newEmail}); err != nil {
		return fmt.Errorf("failed to render email template: %w", err)
	}
	return s.send(oldEmail, "Your email address was changed", buf.String())
}

func (s *SMTPSender) SendPasswordChangedNotice(to string) error {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "account_password_changed.gohtml", EmailData{Issuer: s.issuer}); err != nil {
		return fmt.Errorf("failed to render email template: %w", err)
	}
	return s.send(to, "Your password was changed", buf.String())
}

func (s *SMTPSender) SendAccountDeletionEmail(to, cancelToken string) error {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "account_deletion.gohtml", EmailData{Issuer: s.issuer, Token: cancelToken}); err != nil {
		return fmt.Errorf("failed to render email template: %w", err)
	}
	return s.send(to, "Account deletion scheduled", buf.String())
}

// Deliver sends an already-rendered HTML body to a recipient. Used by
// the outbox worker; the high-level Send* methods on this type render
// a template and then call this. Exposed so the worker can deliver
// without re-rendering.
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
