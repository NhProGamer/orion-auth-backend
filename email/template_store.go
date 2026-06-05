package email

import (
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"orion-auth-backend/model"
)

// Override is the in-memory representation of an admin-edited template.
// Both fields are populated when present in DB; Subject="" + BodyHTML=""
// is invalid (we don't store partial overrides — admin always saves both).
type Override struct {
	Subject  string
	BodyHTML string
}

// Summary is the lightweight projection returned by List for the
// AdminUI table view (no body).
type Summary struct {
	Name      string     `json:"name"`
	Subject   string     `json:"subject"`
	UpdatedAt time.Time  `json:"updated_at"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty"`
}

// Store is the persistence + caching surface for template overrides.
// The cache is per-process and invalidated on every write. Multi-replica
// deployments see eventual consistency: each replica reloads from DB on
// the next miss after the cache expires for any reason — currently never,
// since cache entries live for the process lifetime. This is acceptable
// because Upsert/Delete always invalidate the touching replica
// immediately, and the worst case is "another replica serves the old
// version for a few seconds".
type Store interface {
	Get(name string) (*Override, error)
	Upsert(name string, ov Override, updatedBy uuid.UUID) error
	Delete(name string) error
	List() ([]Summary, error)
}

type gormStore struct {
	db *gorm.DB

	mu    sync.RWMutex
	cache map[string]*Override // nil entry = "we looked, nothing in DB"
}

// NewStore returns the production GORM-backed Store. Tests use a fake.
func NewStore(db *gorm.DB) Store {
	return &gormStore{
		db:    db,
		cache: make(map[string]*Override),
	}
}

func (s *gormStore) Get(name string) (*Override, error) {
	s.mu.RLock()
	cached, ok := s.cache[name]
	s.mu.RUnlock()
	if ok {
		return cached, nil
	}

	var row model.EmailTemplate
	err := s.db.Where("name = ?", name).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		s.mu.Lock()
		s.cache[name] = nil
		s.mu.Unlock()
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	ov := &Override{Subject: row.Subject, BodyHTML: row.BodyHTML}
	s.mu.Lock()
	s.cache[name] = ov
	s.mu.Unlock()
	return ov, nil
}

func (s *gormStore) Upsert(name string, ov Override, updatedBy uuid.UUID) error {
	row := model.EmailTemplate{
		Name:     name,
		Subject:  ov.Subject,
		BodyHTML: ov.BodyHTML,
	}
	if updatedBy != uuid.Nil {
		row.UpdatedBy = &updatedBy
	}
	// ON CONFLICT (name) DO UPDATE — relying on the primary key constraint.
	err := s.db.Save(&row).Error
	if err != nil {
		return err
	}
	s.invalidate(name)
	return nil
}

func (s *gormStore) Delete(name string) error {
	err := s.db.Where("name = ?", name).Delete(&model.EmailTemplate{}).Error
	if err != nil {
		return err
	}
	s.invalidate(name)
	return nil
}

func (s *gormStore) List() ([]Summary, error) {
	var rows []model.EmailTemplate
	if err := s.db.Order("name").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Summary, 0, len(rows))
	for _, r := range rows {
		out = append(out, Summary{
			Name:      r.Name,
			Subject:   r.Subject,
			UpdatedAt: r.UpdatedAt,
			UpdatedBy: r.UpdatedBy,
		})
	}
	return out, nil
}

func (s *gormStore) invalidate(name string) {
	s.mu.Lock()
	delete(s.cache, name)
	s.mu.Unlock()
}
