package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all application configuration. Loaded once at startup; missing
// required values cause an immediate, actionable error (fail-fast).
type Config struct {
	GRPCPort int

	DatabaseURL string

	JWTSecret       string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	MaxFailedLogins int
}

// Load reads configuration from environment variables. Returns an error if any
// required variable is absent or malformed.
//
// Database credentials are read from individual env vars (DB_HOST, DB_PORT,
// DB_NAME, DB_USER, DB_PASSWORD, DB_SSLMODE) so that secrets can be injected
// by Kubernetes without embedding them in a connection string.
func Load() (*Config, error) {
	cfg := &Config{}

	var err error
	cfg.GRPCPort, err = envInt("GRPC_PORT", 8080)
	if err != nil {
		return nil, err
	}

	cfg.DatabaseURL, err = buildDatabaseURL()
	if err != nil {
		return nil, err
	}

	cfg.JWTSecret = os.Getenv("JWT_SECRET")
	if cfg.JWTSecret == "" {
		return nil, errors.New("JWT_SECRET is required")
	}

	cfg.AccessTokenTTL, err = envDuration("ACCESS_TOKEN_TTL", 15*time.Minute)
	if err != nil {
		return nil, err
	}

	cfg.RefreshTokenTTL, err = envDuration("REFRESH_TOKEN_TTL", 7*24*time.Hour)
	if err != nil {
		return nil, err
	}

	cfg.MaxFailedLogins, err = envInt("MAX_FAILED_LOGINS", 5)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// buildDatabaseURL assembles a PostgreSQL DSN from individual env vars.
// Required: DB_HOST, DB_NAME, DB_USER, DB_PASSWORD.
// Optional: DB_PORT (default 5432), DB_SSLMODE (default disable).
func buildDatabaseURL() (string, error) {
	required := map[string]string{
		"DB_HOST":     os.Getenv("DB_HOST"),
		"DB_NAME":     os.Getenv("DB_NAME"),
		"DB_USER":     os.Getenv("DB_USER"),
		"DB_PASSWORD": os.Getenv("DB_PASSWORD"),
	}
	for k, v := range required {
		if v == "" {
			return "", fmt.Errorf("%s is required", k)
		}
	}

	port := os.Getenv("DB_PORT")
	if port == "" {
		port = "5432"
	}
	sslmode := os.Getenv("DB_SSLMODE")
	if sslmode == "" {
		sslmode = "disable"
	}
	schema := os.Getenv("DB_SCHEMA")
	if schema == "" {
		schema = "xdata"
	}

	return fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=%s&search_path=%s",
		required["DB_USER"], required["DB_PASSWORD"],
		required["DB_HOST"], port,
		required["DB_NAME"], sslmode, schema,
	), nil
}

func envInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, errors.New(key + " must be an integer: " + err.Error())
	}
	return n, nil
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, errors.New(key + " must be a valid duration (e.g. 15m, 7h): " + err.Error())
	}
	return d, nil
}
