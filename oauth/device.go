package oauth

import (
	"crypto/rand"
	"log/slog"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"orion-auth-backend/crypto"
	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
	"orion-auth-backend/session"
)

const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ" // 20 chars, no vowels, no ambiguous

// DeviceAuthResponse is the response for POST /device_authorization (RFC 8628).
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func (s *Service) InitDeviceAuthorization(client *model.OAuthClient, scope, issuer string) (*DeviceAuthResponse, error) {
	if !client.HasGrantType("urn:ietf:params:oauth:grant-type:device_code") {
		return nil, pkg.ErrUnauthorizedClient("client is not authorized for device_code grant")
	}

	scopes := client.ValidateScopes(parseSpaceDelimited(scope))

	rawCode, codeHash, err := crypto.GenerateOpaqueToken()
	if err != nil {
		return nil, pkg.ErrServerError("failed to generate device code")
	}

	userCode, err := generateUserCode()
	if err != nil {
		return nil, pkg.ErrServerError("failed to generate user code")
	}

	dc := &model.DeviceCode{
		DeviceCodeHash: codeHash,
		UserCode:       userCode,
		ClientID:       client.ID,
		Scopes:         pq.StringArray(scopes),
		Status:         "pending",
		IntervalSecs:   5,
		ExpiresAt:      time.Now().Add(s.cfg.DeviceCodeTTL),
	}

	if err := s.repo.CreateDeviceCode(dc); err != nil {
		return nil, pkg.ErrServerError("failed to create device code")
	}

	verificationURI := issuer + "/device/verify"

	slog.Info("device authorization initiated", "client_id", client.ID, "user_code", userCode)
	return &DeviceAuthResponse{
		DeviceCode:              rawCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURI + "?code=" + userCode,
		ExpiresIn:               int(s.cfg.DeviceCodeTTL.Seconds()),
		Interval:                5,
	}, nil
}

// DeviceVerify checks the user code and returns device info.
type DeviceVerifyInput struct {
	UserCode string `json:"user_code" binding:"required"`
}

type DeviceVerifyResponse struct {
	UserCode   string   `json:"user_code"`
	ClientName string   `json:"client_name"`
	Scopes     []string `json:"scopes"`
}

func (s *Service) DeviceVerify(userCode string) (*DeviceVerifyResponse, error) {
	dc, err := s.repo.FindDeviceCodeByUserCode(userCode)
	if err != nil || dc == nil {
		return nil, pkg.ErrInvalidGrant("invalid user code")
	}
	if dc.IsExpired() {
		return nil, pkg.ErrExpiredToken("device code expired")
	}
	if dc.Status != "pending" {
		return nil, pkg.ErrInvalidGrant("device code already " + dc.Status)
	}

	client, _ := s.repo.findClient(dc.ClientID.String())
	name := ""
	if client != nil {
		name = client.Name
	}

	return &DeviceVerifyResponse{
		UserCode:   dc.UserCode,
		ClientName: name,
		Scopes:     dc.Scopes,
	}, nil
}

// DeviceApprove approves/denies the device code after user authentication.
type DeviceApproveInput struct {
	UserCode string `json:"user_code" binding:"required"`
	Approved bool   `json:"approved"`
}

func (s *Service) DeviceApprove(input DeviceApproveInput, userID uuid.UUID, ipAddress, userAgent string) error {
	dc, err := s.repo.FindDeviceCodeByUserCode(input.UserCode)
	if err != nil || dc == nil {
		return pkg.ErrInvalidGrant("invalid user code")
	}
	if dc.IsExpired() {
		return pkg.ErrExpiredToken("device code expired")
	}
	if dc.Status != "pending" {
		return pkg.ErrInvalidGrant("device code already " + dc.Status)
	}

	if !input.Approved {
		dc.Status = "denied"
		return s.repo.UpdateDeviceCode(dc)
	}

	// Create session
	sess, err := s.sessionService.Create(session.CreateInput{
		UserID:    userID,
		IPAddress: ipAddress,
		UserAgent: userAgent,
	})
	if err != nil {
		return pkg.ErrServerError("failed to create session")
	}

	dc.Status = "authorized"
	dc.UserID = &userID
	dc.SessionID = &sess.ID

	if err := s.repo.UpdateDeviceCode(dc); err != nil {
		return pkg.ErrServerError("failed to update device code")
	}

	slog.Info("device code approved", "user_code", dc.UserCode, "user_id", userID)
	return nil
}

// ExchangeDeviceCode handles the polling from the device at POST /token.
func (s *Service) ExchangeDeviceCode(client *model.OAuthClient, deviceCodeRaw string) (*TokenResponse, error) {
	codeHash := crypto.HashToken(deviceCodeRaw)

	dc, err := s.repo.FindDeviceCode(codeHash)
	if err != nil || dc == nil {
		return nil, pkg.ErrInvalidGrant("invalid device code")
	}

	if dc.ClientID != client.ID {
		return nil, pkg.ErrInvalidGrant("device code not issued to this client")
	}

	if dc.IsExpired() {
		return nil, pkg.ErrExpiredToken("device code expired")
	}

	// Check polling interval
	now := time.Now()
	if dc.LastPolledAt != nil && now.Sub(*dc.LastPolledAt) < time.Duration(dc.IntervalSecs)*time.Second {
		return nil, pkg.ErrSlowDown()
	}

	// Update last polled
	dc.LastPolledAt = &now
	_ = s.repo.UpdateDeviceCode(dc)

	switch dc.Status {
	case "pending":
		return nil, pkg.ErrAuthorizationPending()
	case "denied":
		return nil, pkg.ErrAccessDenied("user denied the authorization request")
	case "authorized":
		// Issue tokens
		var resp *TokenResponse
		err := s.repo.Transaction(func(tx *Repository) error {
			var txErr error
			resp, txErr = s.issueTokensWithOpts(tx, client, dc.UserID, dc.SessionID, dc.Scopes, issueOpts{
				authTime: dc.CreatedAt,
			})
			return txErr
		})
		if err != nil {
			return nil, err
		}

		// Mark device code as consumed
		dc.Status = "consumed"
		_ = s.repo.UpdateDeviceCode(dc)

		slog.Info("device code exchanged for tokens", "client_id", client.ID, "user_id", dc.UserID)
		return resp, nil
	default:
		return nil, pkg.ErrInvalidGrant("unexpected device code status")
	}
}

func generateUserCode() (string, error) {
	b := make([]byte, 8)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(userCodeAlphabet))))
		if err != nil {
			return "", err
		}
		b[i] = userCodeAlphabet[idx.Int64()]
	}
	return string(b[:4]) + "-" + string(b[4:]), nil
}
