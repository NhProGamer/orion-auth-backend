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
	Issuer string
	Token  string
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
