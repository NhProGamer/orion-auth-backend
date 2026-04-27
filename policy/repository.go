package policy

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"orion-auth-backend/audit"
	"orion-auth-backend/model"
)

type Repository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Create(policy *model.Policy) error {
	return r.db.Create(policy).Error
}

func (r *Repository) FindByID(id uuid.UUID) (*model.Policy, error) {
	var p model.Policy
	err := r.db.Where("id = ?", id).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &p, err
}

func (r *Repository) FindByName(name string) (*model.Policy, error) {
	var p model.Policy
	err := r.db.Where("name = ?", name).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &p, err
}

func (r *Repository) List() ([]model.Policy, error) {
	var policies []model.Policy
	err := r.db.Order("type ASC, priority DESC, name ASC").Find(&policies).Error
	return policies, err
}

func (r *Repository) ListByType(policyType string) ([]model.Policy, error) {
	var policies []model.Policy
	err := r.db.Where("type = ?", policyType).Order("priority DESC, name ASC").Find(&policies).Error
	return policies, err
}

func (r *Repository) ListActive(policyType string) ([]model.Policy, error) {
	var policies []model.Policy
	err := r.db.Where("type = ? AND active = true", policyType).Order("priority DESC, name ASC").Find(&policies).Error
	return policies, err
}

func (r *Repository) ListAllActive() ([]model.Policy, error) {
	var policies []model.Policy
	err := r.db.Where("active = true").Order("type ASC, priority DESC").Find(&policies).Error
	return policies, err
}

func (r *Repository) Update(policy *model.Policy) error {
	return r.db.Save(policy).Error
}

func (r *Repository) Delete(id uuid.UUID) error {
	return r.db.Delete(&model.Policy{}, "id = ?", id).Error
}

// Aggregated decision stats sourced from the audit_logs table.

type StatsBucket struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

type Stats struct {
	WindowFrom    time.Time         `json:"window_from"`
	WindowTo      time.Time         `json:"window_to"`
	TotalDenies   int64             `json:"total_denies"`
	ByPolicyName  []StatsBucket     `json:"by_policy_name"`
	ByPolicyType  []StatsBucket     `json:"by_policy_type"`
	RecentDenies  []model.AuditLog  `json:"recent_denies"`
}

// Stats aggregates policy denial audit logs in the given window.
// limit caps both top-N buckets and recent denies; recent default 10.
func (r *Repository) Stats(from, to time.Time, limit int) (*Stats, error) {
	if limit <= 0 {
		limit = 10
	}
	scope := r.db.Model(&model.AuditLog{}).
		Where("action = ?", audit.ActionPolicyDenied).
		Where("created_at >= ? AND created_at < ?", from, to)

	var total int64
	if err := scope.Count(&total).Error; err != nil {
		return nil, err
	}

	byName, err := r.aggregate(from, to, "metadata->>'policy_name'", limit)
	if err != nil {
		return nil, err
	}
	byType, err := r.aggregate(from, to, "metadata->>'policy_type'", limit)
	if err != nil {
		return nil, err
	}

	var recent []model.AuditLog
	if err := r.db.Model(&model.AuditLog{}).
		Where("action = ?", audit.ActionPolicyDenied).
		Where("created_at >= ? AND created_at < ?", from, to).
		Order("created_at DESC").
		Limit(limit).
		Find(&recent).Error; err != nil {
		return nil, err
	}

	return &Stats{
		WindowFrom:   from,
		WindowTo:     to,
		TotalDenies:  total,
		ByPolicyName: byName,
		ByPolicyType: byType,
		RecentDenies: recent,
	}, nil
}

func (r *Repository) aggregate(from, to time.Time, expr string, limit int) ([]StatsBucket, error) {
	var rows []StatsBucket
	err := r.db.Model(&model.AuditLog{}).
		Select(expr+" AS key, COUNT(*) AS count").
		Where("action = ?", audit.ActionPolicyDenied).
		Where("created_at >= ? AND created_at < ?", from, to).
		Where(expr + " IS NOT NULL").
		Group("key").
		Order("count DESC").
		Limit(limit).
		Scan(&rows).Error
	return rows, err
}
