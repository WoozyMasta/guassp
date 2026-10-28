// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

// Package web exposes the CI and manual sync APIs and health endpoints.
package web

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/woozymasta/guassp/internal/httpclient"
	"github.com/woozymasta/guassp/internal/observability"
	"github.com/woozymasta/guassp/internal/rate"
	"github.com/woozymasta/guassp/internal/scheduler"
	"github.com/woozymasta/guassp/internal/web/ui"
)

const (
	maxCIBodyBytes     = 16 << 10
	maxManualBodyBytes = 16 << 10
)

// NewServer creates an HTTP handler for CI, manual sync, and health endpoints.
func NewServer(
	gitLabClient GitLabClient,
	syncScheduler SyncScheduler,
	logger zerolog.Logger,
	options Options,
) (*Server, error) {
	if gitLabClient == nil || syncScheduler == nil {
		return nil, errors.New("GitLab client and scheduler are required")
	}
	if err := validateBasePath(options.BasePath); err != nil {
		return nil, fmt.Errorf("configure web base path: %w", err)
	}
	if (options.BasicUser == "") != (options.BasicPassword == "") {
		return nil, errors.New("both web Basic credentials must be configured together")
	}
	if (options.MetricsBasicUser == "") != (options.MetricsBasicPassword == "") {
		return nil, errors.New("both metrics Basic credentials must be configured together")
	}
	if options.MetricsToken != "" && options.MetricsBasicUser != "" {
		return nil, errors.New("configure either metrics bearer token or Basic credentials, not both")
	}
	if options.EnableManualFullSync && options.FullSync == nil {
		return nil, errors.New("manual full sync requires a full-sync controller")
	}

	resolver, err := newProjectResolver(gitLabClient, options.GitLabBaseURL)
	if err != nil {
		return nil, err
	}

	limiter, err := rate.NewLimiter(options.SyncRate)
	if err != nil {
		return nil, fmt.Errorf("configure manual sync rate limit: %w", err)
	}

	if options.Observability == nil {
		options.Observability = observability.New(options.BuildVersion, options.BuildCommit, false)
	}
	if options.StartedAt.IsZero() {
		options.StartedAt = time.Now()
	}
	if statsSource, ok := syncScheduler.(interface{ Stats() scheduler.Stats }); ok {
		options.Observability.SetSchedulerStats(statsSource)
	}
	if observerClient, ok := gitLabClient.(interface {
		SetObserver(httpclient.RequestObserver)
	}); ok {
		observerClient.SetObserver(options.Observability)
	}

	if loggerClient, ok := gitLabClient.(interface{ SetLogger(zerolog.Logger) }); ok {
		loggerClient.SetLogger(logger)
	}

	var (
		pages        *template.Template
		pagesHandler http.Handler
	)
	if !options.DisableWeb {
		pages, err = ui.Templates(options.BasePath)
		if err != nil {
			return nil, fmt.Errorf("load web UI: %w", err)
		}
		pagesHandler, err = ui.Assets()
		if err != nil {
			return nil, fmt.Errorf("load web UI assets: %w", err)
		}
	}

	server := &Server{
		logger:               logger.With().Str("component", "http").Logger(),
		jobValidator:         gitLabClient,
		scheduler:            syncScheduler,
		basePath:             options.BasePath,
		projectResolver:      resolver,
		limiter:              limiter,
		basicUser:            options.BasicUser,
		basicPassword:        options.BasicPassword,
		metricsToken:         options.MetricsToken,
		metricsBasicUser:     options.MetricsBasicUser,
		metricsBasicPass:     options.MetricsBasicPassword,
		allowJobTokenBody:    options.AllowJobTokenBody,
		templates:            pages,
		observability:        options.Observability,
		apiToken:             options.APIToken,
		buildVersion:         options.BuildVersion,
		buildCommit:          options.BuildCommit,
		startedAt:            options.StartedAt,
		fullSync:             options.FullSync,
		enableManualFullSync: options.EnableManualFullSync,
		gateSyncUntilReady:   options.GateSyncUntilReady,
		mux:                  http.NewServeMux(),
	}

	registerAPI := func(pattern string, handler http.Handler) {
		server.mux.Handle(pattern, protectAPI(handler, server.apiToken))
	}
	registerSyncAPI := func(pattern string, handler http.Handler) {
		if server.gateSyncUntilReady {
			handler = server.requireReady(handler)
		}
		server.mux.Handle(pattern, protectAPI(handler, server.apiToken))
	}
	registerSyncAPI("POST /api/v1/sync", http.HandlerFunc(server.sync))
	if server.enableManualFullSync {
		registerSyncAPI("POST /api/v1/full-sync", http.HandlerFunc(server.fullSyncAPI))
	}
	server.mux.HandleFunc("GET /healthz", server.health)
	server.mux.HandleFunc("GET /readyz", server.readiness)
	if !options.DisableMetrics {
		server.mux.Handle("GET /metrics", protectMetrics(
			server.observability.Handler(),
			server.metricsToken,
			server.metricsBasicUser,
			server.metricsBasicPass,
		))
	}
	registerAPI("GET /api/v1/status", http.HandlerFunc(server.status))
	registerAPI("GET /api/v1/runs", http.HandlerFunc(server.runs))
	if !options.DisableWeb {
		server.mux.Handle("GET /assets/", pagesHandler)
	}
	if !options.DisableWeb {
		registerSyncAPI("POST /api/v1/projects/sync", http.HandlerFunc(server.manualSync))
		server.mux.HandleFunc("GET /{$}", server.home)
		var homeSubmit http.Handler = http.HandlerFunc(server.homeSubmit)
		if server.gateSyncUntilReady {
			homeSubmit = server.requireReady(homeSubmit)
		}
		server.mux.Handle("POST /{$}", homeSubmit)
		server.mux.HandleFunc("GET /stats", server.statsPage)
	}

	return server, nil
}

// ServeHTTP dispatches a request through the registered route patterns.
func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if server.basePath != "" &&
		(request.URL.Path == server.basePath || strings.HasPrefix(request.URL.Path, server.basePath+"/")) {
		request = request.Clone(request.Context())
		requestURL := *request.URL
		requestURL.Path = strings.TrimPrefix(requestURL.Path, server.basePath)
		requestURL.RawPath = ""
		if requestURL.Path == "" {
			requestURL.Path = "/"
		}
		request.URL = &requestURL
	}
	server.mux.ServeHTTP(writer, request)
}

// SetReady reports whether startup preflight checks have passed.
func (server *Server) SetReady(ready bool) {
	server.ready.Store(ready)
}

// MarkReady reports that startup preflight checks have passed.
func (server *Server) MarkReady() {
	server.SetReady(true)
}

// health reports process liveness without checking upstream availability.
func (server *Server) health(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

// readiness reports whether the HTTP and scheduler startup sequence completed.
func (server *Server) readiness(writer http.ResponseWriter, _ *http.Request) {
	if !server.ready.Load() {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
}

// requireReady rejects work requests until upstream preflight checks pass.
func (server *Server) requireReady(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !server.ready.Load() {
			writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
			return
		}
		next.ServeHTTP(writer, request)
	})
}

// status reports process, scheduler, full-sync, and latest upstream state.
func (server *Server) status(writer http.ResponseWriter, _ *http.Request) {
	status := map[string]any{
		"version":        server.buildVersion,
		"commit":         server.buildCommit,
		"uptime_seconds": max(0, int64(time.Since(server.startedAt).Seconds())),
		"upstreams":      server.observability.Upstreams(),
	}
	if schedulerStats, ok := server.scheduler.(interface{ Stats() scheduler.Stats }); ok {
		status["scheduler"] = schedulerStats.Stats()
	}
	if server.fullSync != nil {
		status["full_sync"] = server.fullSync.Status()
	}
	writeJSON(writer, http.StatusOK, status)
}

// runs returns the newest bounded run summaries.
func (server *Server) runs(writer http.ResponseWriter, request *http.Request) {
	limit := 50
	if value := request.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 {
			writeError(writer, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = parsed
	}
	writeJSON(writer, http.StatusOK, map[string]any{"runs": server.observability.Runs(limit)})
}
