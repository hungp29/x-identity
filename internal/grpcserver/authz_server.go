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

// AuthzServer implements the gRPC AuthzService.
type AuthzServer struct {
	identityv1.UnimplementedAuthzServiceServer
	authz *service.AuthzService
}

// NewAuthzServer creates an AuthzServer.
func NewAuthzServer(authz *service.AuthzService) *AuthzServer {
	return &AuthzServer{authz: authz}
}

func (s *AuthzServer) CheckPermission(ctx context.Context, req *identityv1.CheckPermissionRequest) (*identityv1.CheckPermissionResponse, error) {
	if req.UserId == "" || req.Resource == "" || req.Action == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id, resource, and action are required")
	}

	allowed, err := s.authz.CheckPermission(ctx, req.UserId, req.Resource, req.Action)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "check permission: %v", err)
	}

	return &identityv1.CheckPermissionResponse{Allowed: allowed}, nil
}

func (s *AuthzServer) GetUserPermissions(ctx context.Context, req *identityv1.GetUserPermissionsRequest) (*identityv1.GetUserPermissionsResponse, error) {
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	perms, err := s.authz.GetUserPermissions(ctx, req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get user permissions: %v", err)
	}

	return &identityv1.GetUserPermissionsResponse{
		Permissions: toProtoPermissions(perms),
	}, nil
}

func (s *AuthzServer) AssignRole(ctx context.Context, req *identityv1.AssignRoleRequest) (*identityv1.AssignRoleResponse, error) {
	if req.UserId == "" || req.RoleName == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id and role_name are required")
	}

	err := s.authz.AssignRole(ctx, req.UserId, req.RoleName, req.ExpiresAt, req.GrantedBy)
	if errors.Is(err, service.ErrUserNotFound) {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	if errors.Is(err, service.ErrRoleNotFound) {
		return nil, status.Error(codes.NotFound, "role not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "assign role: %v", err)
	}

	return &identityv1.AssignRoleResponse{}, nil
}

func (s *AuthzServer) RevokeRole(ctx context.Context, req *identityv1.RevokeRoleRequest) (*identityv1.RevokeRoleResponse, error) {
	if req.UserId == "" || req.RoleName == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id and role_name are required")
	}

	err := s.authz.RevokeRole(ctx, req.UserId, req.RoleName)
	if errors.Is(err, service.ErrRoleNotFound) {
		return nil, status.Error(codes.NotFound, "role not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "revoke role: %v", err)
	}

	return &identityv1.RevokeRoleResponse{}, nil
}

// toProtoPermissions converts domain Permission slice to protobuf.
func toProtoPermissions(perms []model.Permission) []*identityv1.Permission {
	out := make([]*identityv1.Permission, len(perms))
	for i, p := range perms {
		out[i] = &identityv1.Permission{
			Id:          p.ID,
			Resource:    p.Resource,
			Action:      p.Action,
			Description: p.Description,
		}
	}
	return out
}
