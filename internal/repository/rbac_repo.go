package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hungp29/x-identity/internal/model"
)

// RBACRepo handles all database operations for roles, permissions, and assignments.
type RBACRepo struct {
	pool *pgxpool.Pool
}

// NewRBACRepo creates an RBACRepo backed by the given pool.
func NewRBACRepo(pool *pgxpool.Pool) *RBACRepo {
	return &RBACRepo{pool: pool}
}

// FindRoleByName looks up a role by name. Returns ErrNotFound if absent.
func (r *RBACRepo) FindRoleByName(ctx context.Context, name string) (*model.Role, error) {
	const q = `
		SELECT id, name, description, is_system, created_at, updated_at
		FROM   roles
		WHERE  name = $1`

	row := r.pool.QueryRow(ctx, q, name)
	var role model.Role
	err := row.Scan(&role.ID, &role.Name, &role.Description, &role.IsSystem, &role.CreatedAt, &role.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find role by name: %w", err)
	}
	return &role, nil
}

// GetUserRoleNames returns the names of all non-expired roles assigned to a user.
func (r *RBACRepo) GetUserRoleNames(ctx context.Context, userID string) ([]string, error) {
	const q = `
		SELECT ro.name
		FROM   user_roles ur
		JOIN   roles ro ON ro.id = ur.role_id
		WHERE  ur.user_id = $1
		  AND  (ur.expires_at IS NULL OR ur.expires_at > now())`

	rows, err := r.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("get user role names: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan role name: %w", err)
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// GetUserPermissions returns all permissions for a user via their active roles.
// Super-admin wildcard (*:*) is included when the user holds the super_admin role.
func (r *RBACRepo) GetUserPermissions(ctx context.Context, userID string) ([]model.Permission, error) {
	const q = `
		SELECT DISTINCT p.id, p.resource, p.action, COALESCE(p.description, '')
		FROM   user_roles ur
		JOIN   roles ro ON ro.id = ur.role_id
		JOIN   role_permissions rp ON rp.role_id = ro.id
		JOIN   permissions p ON p.id = rp.permission_id
		WHERE  ur.user_id = $1
		  AND  (ur.expires_at IS NULL OR ur.expires_at > now())`

	rows, err := r.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("get user permissions: %w", err)
	}
	defer rows.Close()

	var perms []model.Permission
	for rows.Next() {
		var p model.Permission
		if err := rows.Scan(&p.ID, &p.Resource, &p.Action, &p.Description); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

// AssignRole grants a role to a user. If the user already has the role, it is a no-op.
func (r *RBACRepo) AssignRole(ctx context.Context, userID, roleID string, grantedBy *string, expiresAt *time.Time) error {
	const q = `
		INSERT INTO user_roles (user_id, role_id, granted_by, expires_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, role_id) DO UPDATE
		    SET granted_by = EXCLUDED.granted_by,
		        expires_at  = EXCLUDED.expires_at,
		        granted_at  = now()`

	_, err := r.pool.Exec(ctx, q, userID, roleID, grantedBy, expiresAt)
	if err != nil {
		return fmt.Errorf("assign role: %w", err)
	}
	return nil
}

// RevokeRole removes a role assignment for a user. Silent if the assignment does not exist.
func (r *RBACRepo) RevokeRole(ctx context.Context, userID, roleID string) error {
	const q = `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`
	_, err := r.pool.Exec(ctx, q, userID, roleID)
	if err != nil {
		return fmt.Errorf("revoke role: %w", err)
	}
	return nil
}
