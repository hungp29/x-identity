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

// SessionRepo handles all database operations for sessions.
type SessionRepo struct {
	pool *pgxpool.Pool
}

// NewSessionRepo creates a SessionRepo backed by the given pool.
func NewSessionRepo(pool *pgxpool.Pool) *SessionRepo {
	return &SessionRepo{pool: pool}
}

// Create inserts a new session row.
func (r *SessionRepo) Create(ctx context.Context, userID, tokenHash, ipAddress, userAgent string, expiresAt time.Time) (*model.Session, error) {
	const q = `
		INSERT INTO sessions (user_id, token_hash, expires_at, ip_address, user_agent)
		VALUES ($1, $2, $3, $4::inet, $5)
		RETURNING id, user_id, token_hash, expires_at, revoked_at, ip_address::text, user_agent, created_at`

	row := r.pool.QueryRow(ctx, q, userID, tokenHash, expiresAt, ipAddress, userAgent)
	s, err := scanSession(row)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	return s, nil
}

// FindByTokenHash looks up an active session by its token hash.
// Returns ErrNotFound if no matching session exists.
func (r *SessionRepo) FindByTokenHash(ctx context.Context, tokenHash string) (*model.Session, error) {
	const q = `
		SELECT id, user_id, token_hash, expires_at, revoked_at, ip_address::text, user_agent, created_at
		FROM   sessions
		WHERE  token_hash = $1`

	row := r.pool.QueryRow(ctx, q, tokenHash)
	s, err := scanSession(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find session by token hash: %w", err)
	}
	return s, nil
}

// Revoke marks a session as revoked by setting revoked_at to now.
func (r *SessionRepo) Revoke(ctx context.Context, sessionID string) error {
	const q = `UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`
	_, err := r.pool.Exec(ctx, q, sessionID)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// RevokeByUserID revokes all active sessions belonging to a user.
func (r *SessionRepo) RevokeByUserID(ctx context.Context, userID string) error {
	const q = `UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`
	_, err := r.pool.Exec(ctx, q, userID)
	if err != nil {
		return fmt.Errorf("revoke sessions by user: %w", err)
	}
	return nil
}

func scanSession(row pgx.Row) (*model.Session, error) {
	var s model.Session
	err := row.Scan(
		&s.ID, &s.UserID, &s.TokenHash, &s.ExpiresAt,
		&s.RevokedAt, &s.IPAddress, &s.UserAgent, &s.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &s, nil
}
