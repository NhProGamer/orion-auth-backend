package email

import (
	"fmt"
	"log/slog"

	"github.com/wneessen/go-mail"

	"orion-auth-backend/config"
)

type SMTPSender struct {
	cfg    config.SMTPConfig
	issuer string
}

func NewSMTPSender(cfg config.SMTPConfig, issuer string) *SMTPSender {
	return &SMTPSender{cfg: cfg, issuer: issuer}
}

func (s *SMTPSender) SendVerificationEmail(to, token string) error {
	subject := "Verify your email address"
	body := fmt.Sprintf(
		`<h2>Email Verification</h2>
<p>Please verify your email address by using the following token:</p>
<p><strong>%s</strong></p>
<p>Or make a POST request to:</p>
<pre>POST %s/api/v1/auth/verify-email
{"token": "%s"}</pre>
<p>This token expires in 24 hours.</p>`,
		token, s.issuer, token,
	)

	return s.send(to, subject, body)
}

func (s *SMTPSender) SendPasswordResetEmail(to, token string) error {
	subject := "Reset your password"
	body := fmt.Sprintf(
		`<h2>Password Reset</h2>
<p>Use the following token to reset your password:</p>
<p><strong>%s</strong></p>
<p>Or make a POST request to:</p>
<pre>POST %s/api/v1/auth/reset-password
{"token": "%s", "new_password": "your_new_password"}</pre>
<p>This token expires in 1 hour.</p>`,
		token, s.issuer, token,
	)

	return s.send(to, subject, body)
}

func (s *SMTPSender) SendInvitationEmail(to, token string) error {
	subject := "You've been invited"
	body := fmt.Sprintf(
		`<h2>You've Been Invited</h2>
<p>You have been invited to create an account.</p>
<p>Click the link below to complete your registration:</p>
<p><a href="%s/ui/register?invite=%s">Create your account</a></p>
<p>This invitation expires in 7 days.</p>`,
		s.issuer, token,
	)

	return s.send(to, subject, body)
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
