package model

import "time"

// Role bundles a set of permissions that can be assigned to users.
type Role struct {
	ID          string
	Name        string
	Description string
	IsSystem    bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Permission encodes a single capability as a (resource, action) pair.
type Permission struct {
	ID          string
	Resource    string
	Action      string
	Description string
	CreatedAt   time.Time
}

// UserRole records a role assignment for a user, optionally with an expiry.
type UserRole struct {
	UserID    string
	RoleID    string
	GrantedAt time.Time
	GrantedBy *string
	ExpiresAt *time.Time
}

// IsActive reports whether the role assignment is still valid (not expired).
func (ur *UserRole) IsActive(now time.Time) bool {
	return ur.ExpiresAt == nil || ur.ExpiresAt.After(now)
}
