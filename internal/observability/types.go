// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package observability

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/woozymasta/guassp/internal/reconcile"
	"github.com/woozymasta/guassp/internal/scheduler"
)

const (
	// RunHistoryCapacity is the default number of recent runs retained in memory.
	RunHistoryCapacity    = 256
	maxRunHistoryCapacity = 4096
	runCapacity           = RunHistoryCapacity
	maxRunErrors          = 10
	maxSonarProjects      = 50
	maxStoredTextSize     = 512
)

var (
	// fallbackRunID prevents duplicate fallback identifiers if the system RNG fails.
	fallbackRunID atomic.Uint64
)

// Run is a bounded, safe-to-serve summary of one completed reconciliation.
type Run struct {
	// QueuedAt is when the scheduler accepted this run.
	QueuedAt time.Time `json:"queued_at"`
	// StartedAt is when a worker began reconciliation.
	StartedAt time.Time `json:"started_at"`
	// FinishedAt is when reconciliation completed.
	FinishedAt time.Time `json:"finished_at"`
	// ID is a random identifier for this completed run.
	ID string `json:"id"`
	// Source identifies the CI, manual, or scheduled request source.
	Source string `json:"source"`
	// GitLabProject is the canonical GitLab namespace path.
	GitLabProject string `json:"gitlab_project,omitempty"`
	// Result is the bounded reconciliation status.
	Result reconcile.Status `json:"result"`
	// SonarProjects lists the resolved SonarQube project keys.
	SonarProjects []string `json:"sonar_projects,omitempty"`
	// Errors contains a bounded set of sanitized operation summaries.
	Errors []string `json:"errors,omitempty"`
	// Stages contains independent permission, visibility, and lifecycle outcomes.
	Stages reconcile.StageResults `json:"stages"`
	// Counts contains aggregate reconciliation results.
	Counts reconcile.Counts `json:"counts"`
	// GitLabProjectID identifies the synchronized GitLab project.
	GitLabProjectID int64 `json:"gitlab_project_id"`
	// ErrorsOmitted is the number of summaries omitted by the per-run limit.
	ErrorsOmitted int `json:"errors_omitted,omitempty"`
}

// UpstreamStatus reports the latest observed adapter result without probing it.
type UpstreamStatus struct {
	// LastSuccessAt is the last time an operation succeeded.
	LastSuccessAt time.Time `json:"last_success_at,omitzero"`
	// LastErrorAt is the last time an operation failed.
	LastErrorAt time.Time `json:"last_error_at,omitzero"`
	// State is unknown until an operation observes the upstream.
	State string `json:"state"`
}

// Service owns the explicit Prometheus registry and bounded runtime history.
type Service struct {
	fullSyncDuration  prometheus.Histogram
	syncInflight      prometheus.Collector
	syncQueueHigh     prometheus.Collector
	syncQueueLow      prometheus.Collector
	discoveredGitLab  prometheus.Gauge
	discoveredSonar   prometheus.Gauge
	registry          *prometheus.Registry
	syncTotal         *prometheus.CounterVec
	syncStageTotal    *prometheus.CounterVec
	syncDuration      *prometheus.HistogramVec
	permissionChanges *prometheus.CounterVec
	upstreamRequests  *prometheus.CounterVec
	upstreamDuration  *prometheus.HistogramVec
	fullSyncTotal     *prometheus.CounterVec
	buildInfo         *prometheus.GaugeVec
	upstreams         map[string]UpstreamStatus
	schedulerStats    func() scheduler.Stats
	runs              []Run
	next              int
	count             int
	mu                sync.RWMutex
}
