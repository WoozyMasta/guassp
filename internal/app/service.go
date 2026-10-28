// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

// Package app assembles and runs the Guassp service.
package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/woozymasta/guassp/internal/config"
	"github.com/woozymasta/guassp/internal/discovery"
	"github.com/woozymasta/guassp/internal/domain"
	"github.com/woozymasta/guassp/internal/gitlab"
	"github.com/woozymasta/guassp/internal/observability"
	"github.com/woozymasta/guassp/internal/reconcile"
	"github.com/woozymasta/guassp/internal/scheduler"
	"github.com/woozymasta/guassp/internal/sonar"
	"github.com/woozymasta/guassp/internal/version"
	"github.com/woozymasta/guassp/internal/web"
)

const (
	shutdownTimeout    = 10 * time.Second
	schedulerDrainTime = 10 * time.Second
)

// Service owns the listener and runtime components for one process.
type Service struct {
	logger     zerolog.Logger
	listener   net.Listener
	httpServer *http.Server
	webServer  *web.Server
	scheduler  *scheduler.Scheduler
	fullSync   *scheduler.FullSync
	mu         sync.Mutex
	running    bool
}

// New constructs every runtime dependency and binds the listener without
// starting goroutines.
func New(cfg config.RuntimeConfig, logger zerolog.Logger) (*Service, error) {
	serviceLogger := logger.With().Str("component", "service").Logger()
	userAgent := "guassp/" + version.Version
	gitLabClient, err := gitlab.New(cfg.GitLabURL, cfg.GitLab.Token, userAgent)
	if err != nil {
		return nil, fmt.Errorf("create GitLab client: %w", err)
	}
	gitLabClient.SetLogger(logger)

	sonarClient, err := sonar.New(cfg.SonarQubeURL, cfg.SonarQube.Token, userAgent)
	if err != nil {
		return nil, fmt.Errorf("create SonarQube client: %w", err)
	}
	sonarClient.SetLogger(logger)

	observer := observability.NewWithRunHistory(
		version.Version,
		version.Commit,
		cfg.Metrics.IncludeRuntime,
		cfg.Runtime.RunHistory,
	)
	index, err := discovery.NewBindingIndex(sonarClient, cfg.SonarQube.ALMKey)
	if err != nil {
		return nil, fmt.Errorf("create binding discovery: %w", err)
	}
	directory, err := reconcile.NewUserDirectory(sonarClient)
	if err != nil {
		return nil, fmt.Errorf("create SonarQube user directory: %w", err)
	}

	matcher, err := reconcile.NewUserMatcher(
		directory,
		cfg.Users.Match,
		cfg.SonarQube.SkipGroups,
		gitLabClient,
	)
	if err != nil {
		return nil, fmt.Errorf("create user matcher: %w", err)
	}

	discoveryMode := domain.ProjectDiscoveryBinding
	if cfg.Discovery.PathFallback {
		discoveryMode = domain.ProjectDiscoveryBindingPathFallback
	}
	reconciler, err := reconcile.NewReconciler(
		gitLabClient,
		sonarClient,
		index,
		directory,
		matcher,
		reconcile.Options{
			Logger:               logger,
			PermissionObserver:   observer,
			PermissionMap:        cfg.PermissionMap,
			Visibility:           cfg.VisibilityPolicy,
			DiscoveryMode:        discoveryMode,
			SkipGitLabUsers:      cfg.GitLab.SkipUsers,
			SyncUserDeactivation: cfg.Users.Deactivation,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("create reconciler: %w", err)
	}

	projectScheduler, err := scheduler.New(cfg.Runtime.Workers, reconciler, logger, observer.RecordRun)
	if err != nil {
		return nil, fmt.Errorf("create scheduler: %w", err)
	}

	observer.SetSchedulerStats(projectScheduler)
	fullSync, err := scheduler.NewFullSync(cfg.Discovery.FullSyncAt, index, projectScheduler, logger)
	if err != nil {
		return nil, fmt.Errorf("create full-sync runner: %w", err)
	}
	fullSync.SetPreflight(preflight{gitLab: gitLabClient, sonar: sonarClient})

	fullSync.SetObserver(observer)
	handler, err := web.NewServer(gitLabClient, projectScheduler, logger, web.Options{
		StartedAt:            time.Now(),
		FullSync:             fullSync,
		GitLabBaseURL:        cfg.GitLabURL,
		BasePath:             cfg.Web.BasePath,
		Observability:        observer,
		APIToken:             cfg.API.Token,
		BasicUser:            cfg.Web.Username,
		BasicPassword:        cfg.Web.Password,
		BuildVersion:         version.Version,
		BuildCommit:          version.Commit,
		SyncRate:             cfg.WebSyncRate,
		AllowJobTokenBody:    cfg.Compat.JobTokenBody,
		EnableManualFullSync: cfg.Discovery.ManualFullSync,
		DisableWeb:           !cfg.Web.Enabled,
		GateSyncUntilReady:   true,
		DisableMetrics:       !cfg.Metrics.Enabled,
		MetricsToken:         cfg.Metrics.Token,
		MetricsBasicUser:     cfg.Metrics.Username,
		MetricsBasicPassword: cfg.Metrics.Password,
	})
	if err != nil {
		return nil, fmt.Errorf("create HTTP handler: %w", err)
	}
	fullSync.SetReadinessHandler(handler.SetReady)

	listener, err := net.Listen("tcp", cfg.Runtime.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen on %q: %w", cfg.Runtime.Listen, err)
	}

	return &Service{
		logger:   serviceLogger,
		listener: listener,
		httpServer: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       time.Minute,
		},
		webServer: handler,
		scheduler: projectScheduler,
		fullSync:  fullSync,
	}, nil
}

// Run starts workers and HTTP serving, then shuts them down when ctx ends.
func (service *Service) Run(ctx context.Context) error {
	if ctx == nil {
		_ = service.listener.Close()
		return errors.New("service context is required")
	}
	if err := ctx.Err(); err != nil {
		_ = service.listener.Close()
		return nil
	}

	service.mu.Lock()
	if service.running {
		service.mu.Unlock()
		return errors.New("service already running")
	}
	service.running = true
	service.mu.Unlock()

	if err := service.scheduler.Start(context.Background()); err != nil {
		_ = service.listener.Close()
		return fmt.Errorf("start scheduler: %w", err)
	}
	if err := service.fullSync.Start(ctx); err != nil {
		service.scheduler.Cancel()
		<-service.scheduler.Done()
		_ = service.listener.Close()
		return fmt.Errorf("start full-sync runner: %w", err)
	}

	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- service.httpServer.Serve(service.listener)
	}()
	service.logger.Info().Str("listen", service.listener.Addr().String()).Msg("service started")

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-serveErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = fmt.Errorf("serve HTTP: %w", err)
		}
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := service.httpServer.Shutdown(shutdownContext); err != nil {
		service.logger.Warn().Err(err).Msg("graceful HTTP shutdown timed out")
		if closeErr := service.httpServer.Close(); closeErr != nil {
			runErr = errors.Join(runErr, fmt.Errorf("close HTTP server: %w", closeErr))
		}
	}
	service.fullSync.Stop()
	service.scheduler.Drain(schedulerDrainTime)
	service.logger.Info().Msg("service stopped")

	return runErr
}
