package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"google.golang.org/grpc"

	"github.com/hungp29/x-identity/internal/config"
	"github.com/hungp29/x-identity/internal/db"
	"github.com/hungp29/x-identity/internal/grpcserver"
	"github.com/hungp29/x-identity/internal/repository"
	"github.com/hungp29/x-identity/internal/service"
	identityv1 "github.com/hungp29/x-proto/gen/go/identity/v1"
)

// Server wraps the gRPC server and its dependencies.
type Server struct {
	cfg    *config.Config
	logger *slog.Logger
	grpc   *grpc.Server
}

// New builds the gRPC server, wiring all dependencies together.
func New(cfg *config.Config, logger *slog.Logger) (*Server, error) {
	ctx := context.Background()

	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}

	userRepo := repository.NewUserRepo(pool)
	sessionRepo := repository.NewSessionRepo(pool)
	rbacRepo := repository.NewRBACRepo(pool)

	authSvc := service.NewAuthService(
		userRepo, sessionRepo, rbacRepo,
		cfg.JWTSecret,
		cfg.AccessTokenTTL, cfg.RefreshTokenTTL,
		cfg.MaxFailedLogins,
	)
	authzSvc := service.NewAuthzService(rbacRepo, userRepo)

	grpcSrv := grpc.NewServer(
		grpc.UnaryInterceptor(unaryLoggingInterceptor(logger)),
	)

	identityv1.RegisterAuthServiceServer(grpcSrv, grpcserver.NewAuthServer(authSvc))
	identityv1.RegisterAuthzServiceServer(grpcSrv, grpcserver.NewAuthzServer(authzSvc))

	return &Server{cfg: cfg, logger: logger, grpc: grpcSrv}, nil
}

// Run starts listening and serving until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	addr := fmt.Sprintf(":%d", s.cfg.GRPCPort)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	s.logger.Info("grpc server starting", "addr", addr)

	errCh := make(chan error, 1)
	go func() {
		if err := s.grpc.Serve(lis); err != nil {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("shutting down grpc server")
		stopped := make(chan struct{})
		go func() {
			s.grpc.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			s.logger.Warn("graceful stop timed out; forcing stop")
			s.grpc.Stop()
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// unaryLoggingInterceptor logs method, status, and duration for every RPC.
func unaryLoggingInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		lvl := slog.LevelInfo
		if err != nil {
			lvl = slog.LevelWarn
		}
		logger.Log(ctx, lvl, "rpc",
			"method", info.FullMethod,
			"ok", err == nil,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return resp, err
	}
}
