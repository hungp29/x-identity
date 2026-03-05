package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hungp29/x-identity/internal/model"
	"github.com/hungp29/x-identity/internal/repository"
)

// Sentinel errors for authz operations.
var (
	ErrRoleNotFound = errors.New("role not found")
	ErrUserNotFound = errors.New("user not found")
)

// rbacRepo is the subset of RBACRepo needed by AuthzService.
type rbacRepo interface {
	GetUserRoleNames(ctx context.Context, userID string) ([]string, error)
	GetUserPermissions(ctx context.Context, userID string) ([]model.Permission, error)
	FindRoleByName(ctx context.Context, name string) (*model.Role, error)
	AssignRole(ctx context.Context, userID, roleID string, grantedBy *string, expiresAt *time.Time) error
	RevokeRole(ctx context.Context, userID, roleID string) error
}

// userLookup is the subset of UserRepo needed by AuthzService.
type userLookup interface {
	FindByID(ctx context.Context, id string) (*model.User, error)
}

// AuthzService implements authorization logic: permission checks and role management.
type AuthzService struct {
	rbac  rbacRepo
	users userLookup
}

// NewAuthzService constructs an AuthzService.
func NewAuthzService(rbac *repository.RBACRepo, users *repository.UserRepo) *AuthzService {
	return &AuthzService{rbac: rbac, users: users}
}

// CheckPermission reports whether the given user has the specified (resource, action) permission.
// Super-admin wildcard (*:*) grants access to everything.
func (s *AuthzService) CheckPermission(ctx context.Context, userID, resource, action string) (bool, error) {
	perms, err := s.rbac.GetUserPermissions(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("check permission: %w", err)
	}

	for _, p := range perms {
		if (p.Resource == "*" && p.Action == "*") ||
			(p.Resource == resource && p.Action == action) ||
			(p.Resource == resource && p.Action == "*") {
			return true, nil
		}
	}
	return false, nil
}

// GetUserPermissions returns all effective permissions for a user.
func (s *AuthzService) GetUserPermissions(ctx context.Context, userID string) ([]model.Permission, error) {
	perms, err := s.rbac.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user permissions: %w", err)
	}
	return perms, nil
}

// AssignRole grants a role to a user. expiresAtUnix of 0 means permanent.
func (s *AuthzService) AssignRole(ctx context.Context, userID, roleName string, expiresAtUnix int64, grantedByUserID string) error {
	if _, err := s.users.FindByID(ctx, userID); errors.Is(err, repository.ErrNotFound) {
		return ErrUserNotFound
	} else if err != nil {
		return fmt.Errorf("assign role find user: %w", err)
	}

	role, err := s.rbac.FindRoleByName(ctx, roleName)
	if errors.Is(err, repository.ErrNotFound) {
		return ErrRoleNotFound
	}
	if err != nil {
		return fmt.Errorf("assign role find role: %w", err)
	}

	var grantedBy *string
	if grantedByUserID != "" {
		grantedBy = &grantedByUserID
	}

	var expiresAt *time.Time
	if expiresAtUnix > 0 {
		t := time.Unix(expiresAtUnix, 0)
		expiresAt = &t
	}

	return s.rbac.AssignRole(ctx, userID, role.ID, grantedBy, expiresAt)
}

// RevokeRole removes a role from a user. Silent if the assignment does not exist.
func (s *AuthzService) RevokeRole(ctx context.Context, userID, roleName string) error {
	role, err := s.rbac.FindRoleByName(ctx, roleName)
	if errors.Is(err, repository.ErrNotFound) {
		return ErrRoleNotFound
	}
	if err != nil {
		return fmt.Errorf("revoke role find role: %w", err)
	}
	return s.rbac.RevokeRole(ctx, userID, role.ID)
}
