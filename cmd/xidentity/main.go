package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/hungp29/x-identity/internal/config"
	"github.com/hungp29/x-identity/internal/server"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid config", "error", err)
		os.Exit(1)
	}

	srv, err := server.New(cfg, logger)
	if err != nil {
		logger.Error("failed to build server", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		logger.Error("server exited with error", "error", err)
		os.Exit(1)
	}
	logger.Info("shutdown complete")
}
