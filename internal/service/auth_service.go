package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/hungp29/x-identity/internal/model"
	"github.com/hungp29/x-identity/internal/repository"
)

// Sentinel errors returned by AuthService; callers map these to gRPC status codes.
var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrAccountLocked      = errors.New("account is locked")
	ErrEmailTaken         = errors.New("email already registered")
	ErrSessionNotFound    = errors.New("session not found or already revoked")
	ErrSessionExpired     = errors.New("session has expired")
	ErrInvalidToken       = errors.New("invalid or expired token")
)

// TokenPair holds an access token and a refresh token.
type TokenPair struct {
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresIn  int64 // seconds
}

// Claims is the JWT payload for access tokens.
type Claims struct {
	jwt.RegisteredClaims
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// userRepo is the subset of repository.UserRepo used by AuthService.
type userRepo interface {
	Create(ctx context.Context, email, name, passwordHash string) (*model.User, error)
	FindByEmail(ctx context.Context, email string) (*model.User, error)
	FindByID(ctx context.Context, id string) (*model.User, error)
	IncrementFailedLogins(ctx context.Context, userID string, lockThreshold int) error
	ResetFailedLogins(ctx context.Context, userID string) error
}

// sessionRepo is the subset of repository.SessionRepo used by AuthService.
type sessionRepo interface {
	Create(ctx context.Context, userID, tokenHash, ipAddress, userAgent string, expiresAt time.Time) (*model.Session, error)
	FindByTokenHash(ctx context.Context, tokenHash string) (*model.Session, error)
	Revoke(ctx context.Context, sessionID string) error
}

// rbacRoleNames is used to embed roles into the JWT.
type rbacRoleNames interface {
	GetUserRoleNames(ctx context.Context, userID string) ([]string, error)
}

// AuthService implements authentication logic.
type AuthService struct {
	users           userRepo
	sessions        sessionRepo
	roles           rbacRoleNames
	jwtSecret       []byte
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	maxFailedLogins int
}

// NewAuthService constructs an AuthService.
func NewAuthService(
	users *repository.UserRepo,
	sessions *repository.SessionRepo,
	roles *repository.RBACRepo,
	jwtSecret string,
	accessTokenTTL, refreshTokenTTL time.Duration,
	maxFailedLogins int,
) *AuthService {
	return &AuthService{
		users:           users,
		sessions:        sessions,
		roles:           roles,
		jwtSecret:       []byte(jwtSecret),
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
		maxFailedLogins: maxFailedLogins,
	}
}

// Register creates a new user account. Returns ErrEmailTaken if the email is already used.
func (s *AuthService) Register(ctx context.Context, email, name, password string) (*model.User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	u, err := s.users.Create(ctx, email, name, string(hash))
	if errors.Is(err, repository.ErrDuplicate) {
		return nil, ErrEmailTaken
	}
	if err != nil {
		return nil, fmt.Errorf("register user: %w", err)
	}
	return u, nil
}

// Login verifies credentials and issues a token pair on success.
// Returns ErrInvalidCredentials for wrong email/password, ErrAccountLocked for locked accounts.
func (s *AuthService) Login(ctx context.Context, email, password, ipAddress, userAgent string) (*model.User, *TokenPair, error) {
	u, err := s.users.FindByEmail(ctx, email)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, nil, fmt.Errorf("login lookup: %w", err)
	}

	if u.IsLocked() {
		return nil, nil, ErrAccountLocked
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		_ = s.users.IncrementFailedLogins(ctx, u.ID, s.maxFailedLogins)
		return nil, nil, ErrInvalidCredentials
	}

	if err := s.users.ResetFailedLogins(ctx, u.ID); err != nil {
		return nil, nil, fmt.Errorf("reset failed logins: %w", err)
	}

	roles, err := s.roles.GetUserRoleNames(ctx, u.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("get roles: %w", err)
	}

	tokens, err := s.issueTokenPair(ctx, u.ID, u.Email, roles, ipAddress, userAgent)
	if err != nil {
		return nil, nil, err
	}
	return u, tokens, nil
}

// Logout revokes the session identified by the given refresh token.
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	hash := hashToken(refreshToken)
	session, err := s.sessions.FindByTokenHash(ctx, hash)
	if errors.Is(err, repository.ErrNotFound) {
		return ErrSessionNotFound
	}
	if err != nil {
		return fmt.Errorf("logout lookup: %w", err)
	}
	return s.sessions.Revoke(ctx, session.ID)
}

// RefreshToken rotates the refresh token: revokes the old session and issues a new token pair.
func (s *AuthService) RefreshToken(ctx context.Context, refreshToken, ipAddress, userAgent string) (*TokenPair, error) {
	hash := hashToken(refreshToken)
	session, err := s.sessions.FindByTokenHash(ctx, hash)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("refresh lookup: %w", err)
	}

	if !session.IsActive(time.Now()) {
		return nil, ErrSessionExpired
	}

	u, err := s.users.FindByID(ctx, session.UserID)
	if err != nil {
		return nil, fmt.Errorf("refresh find user: %w", err)
	}

	if u.IsLocked() {
		return nil, ErrAccountLocked
	}

	// Revoke old session before issuing new one (token rotation).
	if err := s.sessions.Revoke(ctx, session.ID); err != nil {
		return nil, fmt.Errorf("revoke old session: %w", err)
	}

	roles, err := s.roles.GetUserRoleNames(ctx, u.ID)
	if err != nil {
		return nil, fmt.Errorf("refresh get roles: %w", err)
	}

	return s.issueTokenPair(ctx, u.ID, u.Email, roles, ipAddress, userAgent)
}

// ValidateToken parses and validates a JWT access token, returning its claims.
func (s *AuthService) ValidateToken(_ context.Context, accessToken string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(accessToken, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// issueTokenPair generates a JWT access token and a random refresh token,
// persists the session, and returns the pair.
func (s *AuthService) issueTokenPair(ctx context.Context, userID, email string, roles []string, ipAddress, userAgent string) (*TokenPair, error) {
	now := time.Now()
	accessExpiry := now.Add(s.accessTokenTTL)

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(accessExpiry),
		},
		Email: email,
		Roles: roles,
	}
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	rawRefresh, err := generateSecureToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	refreshExpiry := now.Add(s.refreshTokenTTL)
	if _, err := s.sessions.Create(ctx, userID, hashToken(rawRefresh), ipAddress, userAgent, refreshExpiry); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	return &TokenPair{
		AccessToken:          accessToken,
		RefreshToken:         rawRefresh,
		AccessTokenExpiresIn: int64(s.accessTokenTTL.Seconds()),
	}, nil
}

// generateSecureToken creates a cryptographically random 32-byte hex token.
func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// hashToken returns the SHA-256 hex digest of a raw token string.
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
