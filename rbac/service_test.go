package rbac

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"orion-auth-backend/model"
)

// --- Mock Repository ---

type mockRbacRepo struct {
	createRoleFn         func(role *model.Role) error
	findRoleByIDFn       func(id uuid.UUID) (*model.Role, error)
	findRoleByNameFn     func(name string) (*model.Role, error)
	listRolesFn          func() ([]model.Role, error)
	updateRoleFn         func(role *model.Role) error
	deleteRoleFn         func(id uuid.UUID) error
	listPermissionsFn    func() ([]model.Permission, error)
	findPermsByIDsFn     func(ids []uuid.UUID) ([]model.Permission, error)
	setRolePermsFn       func(roleID uuid.UUID, permIDs []uuid.UUID) error
	getUserRolesFn       func(userID uuid.UUID) ([]model.Role, error)
	assignRoleFn         func(userID, roleID uuid.UUID) error
	removeRoleFn         func(userID, roleID uuid.UUID) error
	getUserPermissionsFn func(userID uuid.UUID) ([]string, error)
}

func (m *mockRbacRepo) CreateRole(role *model.Role) error {
	if m.createRoleFn != nil {
		return m.createRoleFn(role)
	}
	return nil
}

func (m *mockRbacRepo) FindRoleByID(id uuid.UUID) (*model.Role, error) {
	if m.findRoleByIDFn != nil {
		return m.findRoleByIDFn(id)
	}
	return nil, nil
}

func (m *mockRbacRepo) FindRoleByName(name string) (*model.Role, error) {
	if m.findRoleByNameFn != nil {
		return m.findRoleByNameFn(name)
	}
	return nil, nil
}

func (m *mockRbacRepo) ListRoles() ([]model.Role, error) {
	if m.listRolesFn != nil {
		return m.listRolesFn()
	}
	return nil, nil
}

func (m *mockRbacRepo) UpdateRole(role *model.Role) error {
	if m.updateRoleFn != nil {
		return m.updateRoleFn(role)
	}
	return nil
}

func (m *mockRbacRepo) DeleteRole(id uuid.UUID) error {
	if m.deleteRoleFn != nil {
		return m.deleteRoleFn(id)
	}
	return nil
}

func (m *mockRbacRepo) ListPermissions() ([]model.Permission, error) {
	if m.listPermissionsFn != nil {
		return m.listPermissionsFn()
	}
	return nil, nil
}

func (m *mockRbacRepo) FindPermissionsByIDs(ids []uuid.UUID) ([]model.Permission, error) {
	if m.findPermsByIDsFn != nil {
		return m.findPermsByIDsFn(ids)
	}
	return nil, nil
}

func (m *mockRbacRepo) SetRolePermissions(roleID uuid.UUID, permIDs []uuid.UUID) error {
	if m.setRolePermsFn != nil {
		return m.setRolePermsFn(roleID, permIDs)
	}
	return nil
}

func (m *mockRbacRepo) GetUserRoles(userID uuid.UUID) ([]model.Role, error) {
	if m.getUserRolesFn != nil {
		return m.getUserRolesFn(userID)
	}
	return nil, nil
}

func (m *mockRbacRepo) AssignRole(userID, roleID uuid.UUID) error {
	if m.assignRoleFn != nil {
		return m.assignRoleFn(userID, roleID)
	}
	return nil
}

func (m *mockRbacRepo) RemoveRole(userID, roleID uuid.UUID) error {
	if m.removeRoleFn != nil {
		return m.removeRoleFn(userID, roleID)
	}
	return nil
}

func (m *mockRbacRepo) GetUserPermissions(userID uuid.UUID) ([]string, error) {
	if m.getUserPermissionsFn != nil {
		return m.getUserPermissionsFn(userID)
	}
	return nil, nil
}

// --- Helpers ---

func newTestService(repo *mockRbacRepo) *Service {
	return NewService(repo)
}

func makeRole(name string) *model.Role {
	id, _ := uuid.NewV7()
	return &model.Role{
		BaseModel: model.BaseModel{ID: id, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		Name:      name,
	}
}

// --- CreateRole Tests ---

func TestCreateRole_Success(t *testing.T) {
	var created *model.Role
	repo := &mockRbacRepo{
		createRoleFn: func(r *model.Role) error {
			created = r
			return nil
		},
	}
	svc := newTestService(repo)

	role, err := svc.CreateRole(CreateRoleInput{Name: "admin"})
	require.NoError(t, err)
	assert.Equal(t, "admin", role.Name)
	assert.Equal(t, "admin", created.Name)
}

func TestCreateRole_DuplicateName(t *testing.T) {
	existing := makeRole("admin")
	repo := &mockRbacRepo{
		findRoleByNameFn: func(_ string) (*model.Role, error) {
			return existing, nil
		},
	}
	svc := newTestService(repo)

	_, err := svc.CreateRole(CreateRoleInput{Name: "admin"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

// --- GetRole Tests ---

func TestGetRole_Success(t *testing.T) {
	expected := makeRole("editor")
	repo := &mockRbacRepo{
		findRoleByIDFn: func(_ uuid.UUID) (*model.Role, error) {
			return expected, nil
		},
	}
	svc := newTestService(repo)

	got, err := svc.GetRole(expected.ID)
	require.NoError(t, err)
	assert.Equal(t, expected.ID, got.ID)
}

func TestGetRole_NotFound(t *testing.T) {
	repo := &mockRbacRepo{}
	svc := newTestService(repo)

	id, _ := uuid.NewV7()
	_, err := svc.GetRole(id)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- UpdateRole Tests ---

func TestUpdateRole_Success(t *testing.T) {
	existing := makeRole("viewer")
	repo := &mockRbacRepo{
		findRoleByIDFn: func(_ uuid.UUID) (*model.Role, error) {
			return existing, nil
		},
	}
	svc := newTestService(repo)

	newName := "reviewer"
	got, err := svc.UpdateRole(existing.ID, UpdateRoleInput{Name: &newName})
	require.NoError(t, err)
	assert.Equal(t, "reviewer", got.Name)
}

// --- DeleteRole Tests ---

func TestDeleteRole_Success(t *testing.T) {
	existing := makeRole("temp")
	deleted := false
	repo := &mockRbacRepo{
		findRoleByIDFn: func(_ uuid.UUID) (*model.Role, error) {
			return existing, nil
		},
		deleteRoleFn: func(_ uuid.UUID) error {
			deleted = true
			return nil
		},
	}
	svc := newTestService(repo)

	err := svc.DeleteRole(existing.ID)
	require.NoError(t, err)
	assert.True(t, deleted)
}

func TestDeleteRole_NotFound(t *testing.T) {
	repo := &mockRbacRepo{}
	svc := newTestService(repo)

	id, _ := uuid.NewV7()
	err := svc.DeleteRole(id)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- SetRolePermissions Tests ---

func TestSetRolePermissions_Success(t *testing.T) {
	existing := makeRole("admin")
	var gotRoleID uuid.UUID
	var gotPermIDs []uuid.UUID
	repo := &mockRbacRepo{
		findRoleByIDFn: func(_ uuid.UUID) (*model.Role, error) {
			return existing, nil
		},
		setRolePermsFn: func(roleID uuid.UUID, permIDs []uuid.UUID) error {
			gotRoleID = roleID
			gotPermIDs = permIDs
			return nil
		},
	}
	svc := newTestService(repo)

	p1, _ := uuid.NewV7()
	p2, _ := uuid.NewV7()
	err := svc.SetRolePermissions(existing.ID, []uuid.UUID{p1, p2})
	require.NoError(t, err)
	assert.Equal(t, existing.ID, gotRoleID)
	assert.Len(t, gotPermIDs, 2)
}

// --- AssignRole Tests ---

func TestAssignRole_Success(t *testing.T) {
	role := makeRole("admin")
	assigned := false
	repo := &mockRbacRepo{
		findRoleByIDFn: func(_ uuid.UUID) (*model.Role, error) {
			return role, nil
		},
		assignRoleFn: func(_, _ uuid.UUID) error {
			assigned = true
			return nil
		},
	}
	svc := newTestService(repo)

	userID, _ := uuid.NewV7()
	err := svc.AssignRole(userID, role.ID)
	require.NoError(t, err)
	assert.True(t, assigned)
}

func TestAssignRole_RoleNotFound(t *testing.T) {
	repo := &mockRbacRepo{}
	svc := newTestService(repo)

	userID, _ := uuid.NewV7()
	roleID, _ := uuid.NewV7()
	err := svc.AssignRole(userID, roleID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- RemoveRole Tests ---

func TestRemoveRole_Success(t *testing.T) {
	removed := false
	repo := &mockRbacRepo{
		removeRoleFn: func(_, _ uuid.UUID) error {
			removed = true
			return nil
		},
	}
	svc := newTestService(repo)

	userID, _ := uuid.NewV7()
	roleID, _ := uuid.NewV7()
	err := svc.RemoveRole(userID, roleID)
	require.NoError(t, err)
	assert.True(t, removed)
}

// --- HasPermission Tests ---

func TestHasPermission_True(t *testing.T) {
	repo := &mockRbacRepo{
		getUserPermissionsFn: func(_ uuid.UUID) ([]string, error) {
			return []string{"users:read", "users:write"}, nil
		},
	}
	svc := newTestService(repo)

	userID, _ := uuid.NewV7()
	has, err := svc.HasPermission(userID, "users:write")
	require.NoError(t, err)
	assert.True(t, has)
}

func TestHasPermission_False(t *testing.T) {
	repo := &mockRbacRepo{
		getUserPermissionsFn: func(_ uuid.UUID) ([]string, error) {
			return []string{"users:read"}, nil
		},
	}
	svc := newTestService(repo)

	userID, _ := uuid.NewV7()
	has, err := svc.HasPermission(userID, "users:delete")
	require.NoError(t, err)
	assert.False(t, has)
}

// --- GetUserRoles / GetUserPermissions Tests ---

func TestGetUserRoles(t *testing.T) {
	r1 := makeRole("admin")
	r2 := makeRole("editor")
	repo := &mockRbacRepo{
		getUserRolesFn: func(_ uuid.UUID) ([]model.Role, error) {
			return []model.Role{*r1, *r2}, nil
		},
	}
	svc := newTestService(repo)

	userID, _ := uuid.NewV7()
	roles, err := svc.GetUserRoles(userID)
	require.NoError(t, err)
	assert.Len(t, roles, 2)
}

func TestGetUserPermissions(t *testing.T) {
	repo := &mockRbacRepo{
		getUserPermissionsFn: func(_ uuid.UUID) ([]string, error) {
			return []string{"users:read", "roles:manage"}, nil
		},
	}
	svc := newTestService(repo)

	userID, _ := uuid.NewV7()
	perms, err := svc.GetUserPermissions(userID)
	require.NoError(t, err)
	assert.Equal(t, []string{"users:read", "roles:manage"}, perms)
}
