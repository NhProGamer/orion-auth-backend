package oauth

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"orion-auth-backend/model"
	"orion-auth-backend/pkg"
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// --- Client Lookup ---

func (r *Repository) findClient(clientIDStr string) (*model.OAuthClient, error) {
	id, err := uuid.Parse(clientIDStr)
	if err != nil {
		return nil, pkg.ErrInvalidRequest("invalid client_id")
	}
	var client model.OAuthClient
	err = r.db.Where("id = ? AND active = TRUE", id).First(&client).Error
	if err != nil {
		return nil, pkg.ErrInvalidClient("unknown client")
	}
	return &client, nil
}

// --- Authorization Requests ---

func (r *Repository) CreateAuthRequest(req *model.AuthorizationRequest) error {
	return r.db.Create(req).Error
}

func (r *Repository) FindAuthRequest(id uuid.UUID) (*model.AuthorizationRequest, error) {
	var req model.AuthorizationRequest
	err := r.db.Where("id = ? AND expires_at > ?", id, time.Now()).First(&req).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &req, err
}

func (r *Repository) UpdateAuthRequest(req *model.AuthorizationRequest) error {
	return r.db.Save(req).Error
}

func (r *Repository) DeleteAuthRequest(id uuid.UUID) error {
	return r.db.Delete(&model.AuthorizationRequest{}, "id = ?", id).Error
}

// --- Authorization Codes ---

func (r *Repository) CreateAuthCode(code *model.AuthorizationCode) error {
	return r.db.Create(code).Error
}

func (r *Repository) FindAuthCode(codeHash string) (*model.AuthorizationCode, error) {
	var code model.AuthorizationCode
	err := r.db.Where("code_hash = ?", codeHash).First(&code).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &code, err
}

func (r *Repository) MarkAuthCodeUsed(codeHash string) error {
	return r.db.Model(&model.AuthorizationCode{}).Where("code_hash = ?", codeHash).Update("used", true).Error
}

// --- Access Tokens ---

func (r *Repository) CreateAccessToken(token *model.AccessToken) error {
	return r.db.Create(token).Error
}

func (r *Repository) FindAccessToken(id string) (*model.AccessToken, error) {
	var token model.AccessToken
	err := r.db.Where("id = ?", id).First(&token).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &token, err
}

func (r *Repository) RevokeAccessToken(id string) error {
	return r.db.Model(&model.AccessToken{}).Where("id = ?", id).Update("revoked", true).Error
}

func (r *Repository) RevokeAccessTokensByRefreshToken(refreshTokenID string) error {
	return r.db.Model(&model.AccessToken{}).
		Where("refresh_token_id = ? AND revoked = FALSE", refreshTokenID).
		Update("revoked", true).Error
}

func (r *Repository) RevokeAccessTokensBySession(sessionID uuid.UUID) error {
	return r.db.Model(&model.AccessToken{}).
		Where("session_id = ? AND revoked = FALSE", sessionID).
		Update("revoked", true).Error
}

// --- Refresh Tokens ---

func (r *Repository) CreateRefreshToken(token *model.RefreshToken) error {
	return r.db.Create(token).Error
}

func (r *Repository) FindRefreshToken(id string) (*model.RefreshToken, error) {
	var token model.RefreshToken
	err := r.db.Where("id = ?", id).First(&token).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &token, err
}

func (r *Repository) RotateRefreshToken(id string) error {
	now := time.Now()
	return r.db.Model(&model.RefreshToken{}).Where("id = ?", id).Update("rotated_at", now).Error
}

func (r *Repository) RevokeRefreshTokenFamily(familyID uuid.UUID) error {
	return r.db.Model(&model.RefreshToken{}).
		Where("family_id = ? AND revoked = FALSE", familyID).
		Update("revoked", true).Error
}

func (r *Repository) RevokeRefreshTokensBySession(sessionID uuid.UUID) error {
	return r.db.Model(&model.RefreshToken{}).
		Where("session_id = ? AND revoked = FALSE", sessionID).
		Update("revoked", true).Error
}

// --- Consents ---

func (r *Repository) FindActiveConsent(userID, clientID uuid.UUID) (*model.Consent, error) {
	var consent model.Consent
	err := r.db.Where("user_id = ? AND client_id = ? AND revoked_at IS NULL", userID, clientID).First(&consent).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &consent, err
}

func (r *Repository) CreateConsent(consent *model.Consent) error {
	return r.db.Create(consent).Error
}

func (r *Repository) UpdateConsent(consent *model.Consent) error {
	return r.db.Save(consent).Error
}

// --- Device Codes ---

func (r *Repository) CreateDeviceCode(dc *model.DeviceCode) error {
	return r.db.Create(dc).Error
}

func (r *Repository) FindDeviceCode(codeHash string) (*model.DeviceCode, error) {
	var dc model.DeviceCode
	err := r.db.Where("device_code_hash = ?", codeHash).First(&dc).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &dc, err
}

func (r *Repository) FindDeviceCodeByUserCode(userCode string) (*model.DeviceCode, error) {
	var dc model.DeviceCode
	err := r.db.Where("user_code = ?", userCode).First(&dc).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &dc, err
}

func (r *Repository) UpdateDeviceCode(dc *model.DeviceCode) error {
	return r.db.Save(dc).Error
}

// --- Pushed Authorization Requests ---

func (r *Repository) CreatePAR(par *model.PushedAuthorizationRequest) error {
	return r.db.Create(par).Error
}

func (r *Repository) FindPAR(requestURI string) (*model.PushedAuthorizationRequest, error) {
	var par model.PushedAuthorizationRequest
	err := r.db.Where("request_uri = ? AND expires_at > ?", requestURI, time.Now()).First(&par).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &par, err
}

func (r *Repository) DeletePAR(requestURI string) error {
	return r.db.Delete(&model.PushedAuthorizationRequest{}, "request_uri = ?", requestURI).Error
}

// --- Transactions ---

func (r *Repository) Transaction(fn func(tx RepositoryInterface) error) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		return fn(&Repository{db: tx})
	})
}
