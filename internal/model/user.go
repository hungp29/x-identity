package model

import "time"

// User represents a registered account.
type User struct {
	ID              string
	Email           string
	Name            string
	PasswordHash    string
	EmailVerifiedAt *time.Time
	FailedLogins    int
	LockedAt        *time.Time
	LastLoginAt     *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// IsLocked reports whether the account has been locked.
func (u *User) IsLocked() bool { return u.LockedAt != nil }

// IsEmailVerified reports whether the user has confirmed their email address.
func (u *User) IsEmailVerified() bool { return u.EmailVerifiedAt != nil }
