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

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("not found")

// ErrDuplicate is returned when a unique-constraint violation occurs.
var ErrDuplicate = errors.New("duplicate")

// UserRepo handles all database operations for users.
type UserRepo struct {
	pool *pgxpool.Pool
}

// NewUserRepo creates a UserRepo backed by the given pool.
func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{pool: pool}
}

// Create inserts a new user. Returns ErrDuplicate if the email already exists.
func (r *UserRepo) Create(ctx context.Context, email, name, passwordHash string) (*model.User, error) {
	const q = `
		INSERT INTO users (email, name, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id, email, name, password_hash,
		          email_verified_at, failed_login_count, locked_at, last_login_at,
		          created_at, updated_at`

	row := r.pool.QueryRow(ctx, q, email, name, passwordHash)
	u, err := scanUser(row)
	if err != nil {
		if isDuplicateError(err) {
			return nil, ErrDuplicate
		}
		return nil, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

// FindByEmail retrieves a user by email. Returns ErrNotFound if absent.
func (r *UserRepo) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	const q = `
		SELECT id, email, name, password_hash,
		       email_verified_at, failed_login_count, locked_at, last_login_at,
		       created_at, updated_at
		FROM   users
		WHERE  email = $1`

	row := r.pool.QueryRow(ctx, q, email)
	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find user by email: %w", err)
	}
	return u, nil
}

// FindByID retrieves a user by ID. Returns ErrNotFound if absent.
func (r *UserRepo) FindByID(ctx context.Context, id string) (*model.User, error) {
	const q = `
		SELECT id, email, name, password_hash,
		       email_verified_at, failed_login_count, locked_at, last_login_at,
		       created_at, updated_at
		FROM   users
		WHERE  id = $1`

	row := r.pool.QueryRow(ctx, q, id)
	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find user by id: %w", err)
	}
	return u, nil
}

// IncrementFailedLogins increments the failed login counter.
// If the count reaches the lockout threshold, locked_at is also set.
func (r *UserRepo) IncrementFailedLogins(ctx context.Context, userID string, lockThreshold int) error {
	const q = `
		UPDATE users
		SET    failed_login_count = failed_login_count + 1,
		       locked_at = CASE
		           WHEN failed_login_count + 1 >= $2 THEN now()
		           ELSE locked_at
		       END,
		       updated_at = now()
		WHERE  id = $1`

	_, err := r.pool.Exec(ctx, q, userID, lockThreshold)
	if err != nil {
		return fmt.Errorf("increment failed logins: %w", err)
	}
	return nil
}

// ResetFailedLogins clears the failed login counter and updates last_login_at.
func (r *UserRepo) ResetFailedLogins(ctx context.Context, userID string) error {
	const q = `
		UPDATE users
		SET    failed_login_count = 0,
		       last_login_at      = now(),
		       updated_at         = now()
		WHERE  id = $1`

	_, err := r.pool.Exec(ctx, q, userID)
	if err != nil {
		return fmt.Errorf("reset failed logins: %w", err)
	}
	return nil
}

func scanUser(row pgx.Row) (*model.User, error) {
	var u model.User
	err := row.Scan(
		&u.ID, &u.Email, &u.Name, &u.PasswordHash,
		&u.EmailVerifiedAt, &u.FailedLogins, &u.LockedAt, &u.LastLoginAt,
		&u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// isDuplicateError checks if the error is a PostgreSQL unique-constraint violation (code 23505).
func isDuplicateError(err error) bool {
	return err != nil && (containsString(err.Error(), "23505") || containsString(err.Error(), "duplicate key"))
}

func containsString(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsAt(s, sub))
}

func containsAt(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// UpdatedAt is used only for correct tracking of time.
func (r *UserRepo) UpdateLastLogin(ctx context.Context, userID string, at time.Time) error {
	const q = `UPDATE users SET last_login_at = $2, updated_at = now() WHERE id = $1`
	_, err := r.pool.Exec(ctx, q, userID, at)
	return err
}
