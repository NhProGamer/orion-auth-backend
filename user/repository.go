package user

import (
	"errors"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"orion-auth-backend/model"
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// WithTx returns a Repository pointing at tx. The receiver is left
// unchanged so concurrent code paths cannot collide on the underlying
// *gorm.DB handle. The service composes Tx-scoped writes via:
//
//	s.db.Transaction(func(tx *gorm.DB) error {
//	    if err := s.repo.WithTx(tx).Create(u); err != nil { ... }
//	    ...
//	})
func (r *Repository) WithTx(tx *gorm.DB) RepositoryInterface {
	return &Repository{db: tx}
}

func (r *Repository) Create(user *model.User) error {
	return r.db.Create(user).Error
}

func (r *Repository) FindByID(id uuid.UUID) (*model.User, error) {
	var user model.User
	err := r.db.Where("id = ?", id).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &user, err
}

func (r *Repository) FindByEmail(email string) (*model.User, error) {
	var user model.User
	err := r.db.Where("email = ?", email).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &user, err
}

func (r *Repository) Update(user *model.User) error {
	return r.db.Save(user).Error
}

func (r *Repository) UpdateFields(id uuid.UUID, fields map[string]any) error {
	return r.db.Model(&model.User{}).Where("id = ?", id).Updates(fields).Error
}

func (r *Repository) List(page, perPage int) ([]model.User, int64, error) {
	return r.Search("", page, perPage)
}

// Search lists users matching a case-insensitive substring against email,
// display_name, or the stringified ID. An empty query returns all rows.
// The query is filtered DB-side so pagination stays consistent.
func (r *Repository) Search(q string, page, perPage int) ([]model.User, int64, error) {
	var users []model.User
	var total int64

	query := r.db.Model(&model.User{})
	if q != "" {
		like := "%" + strings.ToLower(q) + "%"
		query = query.Where(
			"LOWER(email) LIKE ? OR LOWER(COALESCE(display_name, '')) LIKE ? OR id::text LIKE ?",
			like, like, like,
		)
	}
	query.Count(&total)

	offset := (page - 1) * perPage
	err := query.Offset(offset).Limit(perPage).Order("created_at DESC").Find(&users).Error
	return users, total, err
}

func (r *Repository) Delete(id uuid.UUID) error {
	return r.db.Delete(&model.User{}, "id = ?", id).Error
}

func (r *Repository) FindByResetToken(tokenHash string) (*model.User, error) {
	var user model.User
	err := r.db.Where("password_reset_token = ? AND password_reset_expires_at > NOW()", tokenHash).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &user, err
}

func (r *Repository) FindByVerifyToken(tokenHash string) (*model.User, error) {
	var user model.User
	err := r.db.Where("email_verify_token = ? AND email_verify_expires_at > NOW()", tokenHash).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &user, err
}

func (r *Repository) FindByEmailChangeToken(tokenHash string) (*model.User, error) {
	var user model.User
	err := r.db.Where("email_change_token = ? AND email_change_expires_at > NOW()", tokenHash).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &user, err
}

func (r *Repository) FindByDeletionToken(tokenHash string) (*model.User, error) {
	var user model.User
	err := r.db.Where("deletion_token = ? AND deletion_purge_after > NOW()", tokenHash).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &user, err
}
