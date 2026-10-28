// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

// Package main starts the Guassp service.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"
	"github.com/woozymasta/guassp/internal/app"
	"github.com/woozymasta/guassp/internal/config"
	"github.com/woozymasta/guassp/internal/logger"
	"github.com/woozymasta/guassp/internal/version"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "guassp:", err)
		os.Exit(1)
	}
}

// run loads configuration, constructs the service, and runs it until ctx ends.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 1 && (args[0] == "-v" || args[0] == "--version") {
		return version.Print(stdout)
	}

	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("load .env: %w", err)
	}

	path, explicit, err := config.ResolvePath(args)
	if err != nil {
		return err
	}

	cfg, err := config.Load(path, explicit)
	if err != nil {
		return err
	}

	appLogger, closeOutput, err := logger.Setup(cfg.Log, stdout, stderr)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := closeOutput(); closeErr != nil {
			appLogger.Error().Err(closeErr).Msg("close log output")
		}
	}()

	service, err := app.New(cfg, appLogger)
	if err != nil {
		return fmt.Errorf("initialize service: %w", err)
	}

	appLogger.Info().
		Str("project", "GUASSP").
		Str("url", version.URL).
		Str("version", version.Version).
		Str("commit", version.Commit).
		Str("build_time", version.BuildTime).
		Msg("starting service")

	return service.Run(ctx)
}
