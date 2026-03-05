package model

import "time"

// Session represents a server-side refresh-token record.
// The raw token is sent to the client; only its SHA-256 hash is stored.
type Session struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	RevokedAt *time.Time
	IPAddress string
	UserAgent string
	CreatedAt time.Time
}

// IsActive reports whether the session is still valid (not revoked, not expired).
func (s *Session) IsActive(now time.Time) bool {
	return s.RevokedAt == nil && s.ExpiresAt.After(now)
}
