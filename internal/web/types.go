// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package web

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/woozymasta/guassp/internal/gitlab"
	"github.com/woozymasta/guassp/internal/observability"
	"github.com/woozymasta/guassp/internal/rate"
	"github.com/woozymasta/guassp/internal/scheduler"
)

// JobValidator validates a GitLab CI job token and returns its job and project.
type JobValidator interface {
	// CurrentJob validates a CI job token with GitLab.
	CurrentJob(context.Context, string) (gitlab.Job, error)
}

// GitLabClient provides the authenticated operations required by the HTTP API.
type GitLabClient interface {
	JobValidator
	ProjectLookup
}

// SyncScheduler queues high-priority reconciliation work.
type SyncScheduler interface {
	// Submit queues a project for reconciliation.
	Submit(int64, scheduler.Priority, string) (scheduler.Submission, error)
}

// Options controls CI compatibility and manual-sync access.
type Options struct {
	// StartedAt is the process start time used to report uptime.
	StartedAt time.Time
	// FullSync exposes status and accepts a manual cycle when enabled.
	FullSync FullSyncController
	// GitLabBaseURL restricts accepted manual project URLs to this instance.
	GitLabBaseURL *url.URL
	// SonarQubeBaseURL builds links to synchronized SonarQube projects.
	SonarQubeBaseURL *url.URL
	// Observability provides run history, metrics, and upstream status.
	Observability *observability.Service
	// BasePath is the optional public URL path prefix for routes and generated page links.
	BasePath string
	// APIToken enables bearer authentication for all JSON API endpoints.
	APIToken string
	// BasicUser enables Basic authentication when paired with BasicPassword.
	BasicUser string
	// BasicPassword enables Basic authentication when paired with BasicUser.
	BasicPassword string
	// MetricsToken enables bearer-token authentication for the Prometheus endpoint.
	MetricsToken string
	// MetricsBasicUser enables Basic authentication for the Prometheus endpoint.
	MetricsBasicUser string
	// MetricsBasicPassword is the password paired with MetricsBasicUser.
	MetricsBasicPassword string
	// BuildVersion is the version returned by the status API.
	BuildVersion string
	// BuildCommit is the revision returned by the status API.
	BuildCommit string
	// SyncRate limits manual submissions per observed remote IP.
	SyncRate rate.Limit
	// EnableManualFullSync registers the API endpoint and exposes the web action.
	EnableManualFullSync bool
	// DisableMetrics disables the Prometheus endpoint.
	DisableMetrics bool
	// AllowJobTokenBody enables the legacy JSON job_token transport.
	AllowJobTokenBody bool
	// DisableWeb disables the SSR form and statistics pages.
	DisableWeb bool
	// GateSyncUntilReady rejects sync requests before upstream preflight passes.
	GateSyncUntilReady bool
}

// FullSyncController exposes status and accepts a non-overlapping manual cycle.
type FullSyncController interface {
	// Status returns a copy of the latest full-sync state.
	Status() scheduler.FullSyncStatus
	// Trigger queues a cycle unless another cycle is already queued or running.
	Trigger() bool
}

// Server serves CI sync, manual sync, and health endpoints.
type Server struct {
	logger           zerolog.Logger
	startedAt        time.Time
	jobValidator     JobValidator
	scheduler        SyncScheduler
	fullSync         FullSyncController
	projectResolver  *projectResolver
	gitLabBaseURL    *url.URL
	sonarQubeBaseURL *url.URL
	limiter          *rate.Limiter
	mux              *http.ServeMux
	templates        *template.Template
	observability    *observability.Service
	basePath         string
	apiToken         string
	basicUser        string
	basicPassword    string
	buildVersion     string
	buildCommit      string
	metricsToken     string
	metricsBasicUser string
	metricsBasicPass string
	ready            atomic.Bool
	// enableManualFullSync controls route registration and the console action.
	enableManualFullSync bool
	gateSyncUntilReady   bool
	allowJobTokenBody    bool
}

// ManualSyncResponse reports a queued manually requested project sync.
type ManualSyncResponse struct {
	// Project is the canonical GitLab namespace path.
	Project string `json:"project"`
	// Source identifies this request as manual.
	Source string `json:"source"`
	// Status describes the scheduler state returned to the caller.
	Status string `json:"status"`
	// ProjectID identifies the resolved GitLab project.
	ProjectID int64 `json:"project_id"`
	// Coalesced reports whether the request joined existing project work.
	Coalesced bool `json:"coalesced"`
}

// SyncResponse reports the accepted CI project reconciliation request.
type SyncResponse struct {
	// Source identifies this request as a CI event.
	Source string `json:"source"`
	// Status describes the scheduler state returned to the caller.
	Status string `json:"status"`
	// ProjectID is taken from the validated GitLab job response.
	ProjectID int64 `json:"project_id"`
	// Coalesced reports whether the request joined existing project work.
	Coalesced bool `json:"coalesced"`
}

// FullSyncResponse reports whether a full discovery cycle was queued.
type FullSyncResponse struct {
	// Status is queued when the cycle was accepted.
	Status string `json:"status"`
}

// ErrorResponse contains a sanitized API error message.
type ErrorResponse struct {
	// Error is a stable message that never includes upstream response text.
	Error string `json:"error"`
}

// manualSyncRequest contains the sole accepted manual sync input.
type manualSyncRequest struct {
	// Project accepts a GitLab ID, namespace path, or canonical project URL.
	Project string `json:"project"`
}
