package grpcserver

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/hungp29/x-identity/internal/model"
	"github.com/hungp29/x-identity/internal/service"
	identityv1 "github.com/hungp29/x-proto/gen/go/identity/v1"
)

// AuthServer implements the gRPC AuthService.
type AuthServer struct {
	identityv1.UnimplementedAuthServiceServer
	auth *service.AuthService
}

// NewAuthServer creates an AuthServer.
func NewAuthServer(auth *service.AuthService) *AuthServer {
	return &AuthServer{auth: auth}
}

func (s *AuthServer) Register(ctx context.Context, req *identityv1.RegisterRequest) (*identityv1.RegisterResponse, error) {
	if req.Email == "" || req.Name == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email, name, and password are required")
	}

	u, err := s.auth.Register(ctx, req.Email, req.Name, req.Password)
	if errors.Is(err, service.ErrEmailTaken) {
		return nil, status.Error(codes.AlreadyExists, "email already registered")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "register: %v", err)
	}

	return &identityv1.RegisterResponse{User: toProtoUser(u)}, nil
}

func (s *AuthServer) Login(ctx context.Context, req *identityv1.LoginRequest) (*identityv1.LoginResponse, error) {
	if req.Email == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	u, tokens, err := s.auth.Login(ctx, req.Email, req.Password, req.IpAddress, req.UserAgent)
	if errors.Is(err, service.ErrInvalidCredentials) {
		return nil, status.Error(codes.Unauthenticated, "invalid email or password")
	}
	if errors.Is(err, service.ErrAccountLocked) {
		return nil, status.Error(codes.PermissionDenied, "account is locked")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "login: %v", err)
	}

	return &identityv1.LoginResponse{
		User:   toProtoUser(u),
		Tokens: toProtoTokenPair(tokens),
	}, nil
}

func (s *AuthServer) Logout(ctx context.Context, req *identityv1.LogoutRequest) (*identityv1.LogoutResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	if err := s.auth.Logout(ctx, req.RefreshToken); err != nil {
		if errors.Is(err, service.ErrSessionNotFound) {
			return nil, status.Error(codes.NotFound, "session not found or already revoked")
		}
		return nil, status.Errorf(codes.Internal, "logout: %v", err)
	}

	return &identityv1.LogoutResponse{}, nil
}

func (s *AuthServer) RefreshToken(ctx context.Context, req *identityv1.RefreshTokenRequest) (*identityv1.RefreshTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	tokens, err := s.auth.RefreshToken(ctx, req.RefreshToken, req.IpAddress, req.UserAgent)
	if errors.Is(err, service.ErrSessionNotFound) {
		return nil, status.Error(codes.Unauthenticated, "session not found or already revoked")
	}
	if errors.Is(err, service.ErrSessionExpired) {
		return nil, status.Error(codes.Unauthenticated, "session has expired")
	}
	if errors.Is(err, service.ErrAccountLocked) {
		return nil, status.Error(codes.PermissionDenied, "account is locked")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "refresh token: %v", err)
	}

	return &identityv1.RefreshTokenResponse{Tokens: toProtoTokenPair(tokens)}, nil
}

func (s *AuthServer) ValidateToken(ctx context.Context, req *identityv1.ValidateTokenRequest) (*identityv1.ValidateTokenResponse, error) {
	if req.AccessToken == "" {
		return nil, status.Error(codes.InvalidArgument, "access_token is required")
	}

	claims, err := s.auth.ValidateToken(ctx, req.AccessToken)
	if errors.Is(err, service.ErrInvalidToken) {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired token")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "validate token: %v", err)
	}

	return &identityv1.ValidateTokenResponse{
		UserId: claims.Subject,
		Email:  claims.Email,
		Roles:  claims.Roles,
	}, nil
}

// toProtoUser converts a domain User to its protobuf representation.
func toProtoUser(u *model.User) *identityv1.User {
	return &identityv1.User{
		Id:            u.ID,
		Email:         u.Email,
		Name:          u.Name,
		EmailVerified: u.IsEmailVerified(),
		Locked:        u.IsLocked(),
	}
}

// toProtoTokenPair converts a service TokenPair to its protobuf representation.
func toProtoTokenPair(t *service.TokenPair) *identityv1.TokenPair {
	return &identityv1.TokenPair{
		AccessToken:          t.AccessToken,
		RefreshToken:         t.RefreshToken,
		AccessTokenExpiresIn: t.AccessTokenExpiresIn,
	}
}
