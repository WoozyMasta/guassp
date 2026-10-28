// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

// Package observability stores bounded run history and exports service metrics.
package observability

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/woozymasta/guassp/internal/reconcile"
	"github.com/woozymasta/guassp/internal/scheduler"
)

// New creates an observability service with an isolated Prometheus registry.
func New(version, commit string, includeRuntime bool) *Service {
	return NewWithRunHistory(version, commit, includeRuntime, RunHistoryCapacity)
}

// NewWithRunHistory creates an observability service with configurable bounded run history.
func NewWithRunHistory(version, commit string, includeRuntime bool, runHistory int) *Service {
	if runHistory < 1 {
		runHistory = RunHistoryCapacity
	}
	if runHistory > maxRunHistoryCapacity {
		runHistory = maxRunHistoryCapacity
	}

	service := &Service{
		registry: prometheus.NewRegistry(),
		runs:     make([]Run, runHistory),
		upstreams: map[string]UpstreamStatus{
			"gitlab":    {State: "unknown"},
			"sonarqube": {State: "unknown"},
		},

		syncTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "guassp_sync_total",
			Help: "Completed project reconciliations.",
		}, []string{"source", "result"}),

		syncStageTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "guassp_sync_stage_total",
			Help: "Project reconciliation stage outcomes.",
		}, []string{"source", "stage", "result"}),

		syncDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "guassp_sync_duration_seconds",
			Help:    "Project reconciliation duration.",
			Buckets: prometheus.DefBuckets,
		}, []string{"source", "result"}),

		permissionChanges: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "guassp_permission_changes_total",
			Help: "Permission and visibility changes.",
		}, []string{"action", "permission", "result"}),

		upstreamRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "guassp_upstream_requests_total",
			Help: "Upstream HTTP requests.",
		}, []string{"upstream", "operation", "status_class"}),

		upstreamDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "guassp_upstream_request_duration_seconds",
			Help:    "Upstream HTTP request duration.",
			Buckets: prometheus.DefBuckets,
		}, []string{"upstream", "operation"}),

		fullSyncTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "guassp_full_sync_total",
			Help: "Completed full discovery cycles.",
		}, []string{"result"}),

		fullSyncDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "guassp_full_sync_duration_seconds",
			Help:    "Full discovery cycle duration.",
			Buckets: prometheus.DefBuckets,
		}),

		discoveredGitLab: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "guassp_discovered_gitlab_projects",
			Help: "GitLab projects in the latest binding snapshot.",
		}),

		discoveredSonar: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "guassp_discovered_sonar_projects",
			Help: "SonarQube projects in the latest binding snapshot.",
		}),

		buildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "guassp_build_info", Help: "Build metadata.",
		}, []string{"version", "commit"}),
	}

	service.buildInfo.WithLabelValues(bounded(version), bounded(commit)).Set(1)

	service.syncInflight = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "guassp_sync_inflight",
		Help: "Project reconciliations currently running.",
	}, func() float64 { return float64(service.currentSchedulerStats().Inflight) })

	service.syncQueueHigh = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name:        "guassp_sync_queue",
		Help:        "Queued projects by priority.",
		ConstLabels: prometheus.Labels{"priority": "high"},
	}, func() float64 { return float64(service.currentSchedulerStats().HighQueue) })

	service.syncQueueLow = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name:        "guassp_sync_queue",
		Help:        "Queued projects by priority.",
		ConstLabels: prometheus.Labels{"priority": "low"},
	}, func() float64 { return float64(service.currentSchedulerStats().LowQueue) })

	service.registry.MustRegister(
		service.syncTotal,
		service.syncStageTotal,
		service.syncDuration,
		service.permissionChanges,
		service.upstreamRequests,
		service.upstreamDuration,
		service.fullSyncTotal,
		service.fullSyncDuration,
		service.syncInflight,
		service.syncQueueHigh,
		service.syncQueueLow,
		service.discoveredGitLab,
		service.discoveredSonar,
		service.buildInfo,
	)
	if includeRuntime {
		service.registry.MustRegister(
			collectors.NewGoCollector(),
			collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		)
	}

	return service
}

// SetSchedulerStats connects live scheduler queue metrics to this registry.
func (service *Service) SetSchedulerStats(source interface{ Stats() scheduler.Stats }) {
	service.mu.Lock()

	if source == nil {
		service.schedulerStats = nil
	} else {
		service.schedulerStats = source.Stats
	}

	service.mu.Unlock()
}

// currentSchedulerStats returns a live scheduler snapshot when configured.
func (service *Service) currentSchedulerStats() scheduler.Stats {
	service.mu.RLock()
	source := service.schedulerStats
	service.mu.RUnlock()

	if source == nil {
		return scheduler.Stats{}
	}

	return source()
}

// Registry returns the service-owned registry for custom collectors.
func (service *Service) Registry() *prometheus.Registry { return service.registry }

// Handler exposes metrics from the service-owned registry.
func (service *Service) Handler() http.Handler {
	return promhttp.HandlerFor(service.registry, promhttp.HandlerOpts{})
}

// RunCapacity returns the number of completed runs this service retains.
func (service *Service) RunCapacity() int {
	return len(service.runs)
}

// RecordRun stores one completed run in the fixed-size ring and records metrics.
func (service *Service) RecordRun(run scheduler.Run) {
	status := safeResult(run.Result.Status)
	source := safeSource(run.Source)
	duration := run.FinishedAt.Sub(run.StartedAt).Seconds()
	if duration < 0 {
		duration = 0
	}

	service.syncTotal.WithLabelValues(source, string(status)).Inc()
	service.syncDuration.WithLabelValues(source, string(status)).Observe(duration)
	service.recordStageMetrics(source, run.Result.Stages)
	stored := Run{
		ID:              newRunID(),
		Source:          source,
		GitLabProjectID: run.ProjectID,
		GitLabProject:   bounded(run.Result.GitLabProject),
		SonarProjects:   boundedStrings(run.Result.SonarProjects),
		QueuedAt:        run.QueuedAt,
		StartedAt:       run.StartedAt,
		FinishedAt:      run.FinishedAt,
		Result:          status,
		Stages:          run.Result.Stages,
		Counts:          run.Result.Counts,
	}

	for _, message := range run.Result.Errors {
		if len(stored.Errors) == maxRunErrors {
			break
		}

		stored.Errors = append(stored.Errors, bounded(message))
	}

	stored.ErrorsOmitted = len(run.Result.Errors) - len(stored.Errors)
	service.mu.Lock()

	service.runs[service.next] = stored
	service.next = (service.next + 1) % len(service.runs)
	if service.count < len(service.runs) {
		service.count++
	}

	service.mu.Unlock()
}

// recordStageMetrics exports bounded outcomes for permission, visibility, and deactivation stages.
func (service *Service) recordStageMetrics(source string, stages reconcile.StageResults) {
	for _, stage := range []struct {
		name   string
		result reconcile.StageResult
	}{
		{name: "permissions", result: stages.Permissions},
		{name: "visibility", result: stages.Visibility},
		{name: "deactivation", result: stages.Deactivation},
	} {
		for _, outcome := range []struct {
			name  string
			count int
		}{
			{name: "success", count: stage.result.Succeeded},
			{name: "partial", count: stage.result.Partial},
			{name: "failed", count: stage.result.Failed},
			{name: "skipped", count: stage.result.Skipped},
		} {
			if outcome.count == 0 {
				continue
			}
			service.syncStageTotal.WithLabelValues(source, stage.name, outcome.name).Add(float64(outcome.count))
		}
	}
}

// Runs returns the newest completed runs, capped at the store capacity.
func (service *Service) Runs(limit int) []Run {
	if limit < 1 {
		limit = 50
	}
	if limit > len(service.runs) {
		limit = len(service.runs)
	}

	service.mu.RLock()
	defer service.mu.RUnlock()

	if limit > service.count {
		limit = service.count
	}

	runs := make([]Run, 0, limit)
	for offset := 1; offset <= limit; offset++ {
		index := (service.next - offset + len(service.runs)) % len(service.runs)
		run := service.runs[index]
		run.SonarProjects = append([]string(nil), run.SonarProjects...)
		run.Errors = append([]string(nil), run.Errors...)
		runs = append(runs, run)
	}

	return runs
}

// Upstreams returns a copy of the latest adapter health observations.
func (service *Service) Upstreams() map[string]UpstreamStatus {
	service.mu.RLock()
	defer service.mu.RUnlock()
	return map[string]UpstreamStatus{
		"gitlab":    service.upstreams["gitlab"],
		"sonarqube": service.upstreams["sonarqube"],
	}
}

// ObserveRequest records one bounded upstream HTTP operation.
func (service *Service) ObserveRequest(upstream, operation, statusClass string, duration time.Duration) {
	upstream = safeUpstream(upstream)
	if upstream == "" {
		return
	}

	operation = safeOperation(operation)
	statusClass = safeStatusClass(statusClass)
	service.upstreamRequests.WithLabelValues(upstream, operation, statusClass).Inc()
	service.upstreamDuration.WithLabelValues(upstream, operation).Observe(max(0, duration.Seconds()))
	service.mu.Lock()

	status := service.upstreams[upstream]
	if statusClass == "2xx" {
		status.State, status.LastSuccessAt = "ok", time.Now()
	} else {
		status.State, status.LastErrorAt = "error", time.Now()
	}

	service.upstreams[upstream] = status
	service.mu.Unlock()
}

// ObservePermission records a permission change using bounded labels.
func (service *Service) ObservePermission(action, permission, result string) {
	service.permissionChanges.WithLabelValues(
		safeAction(action),
		safePermission(permission),
		safeResultLabel(result),
	).Inc()
}

// ObserveFullSyncStatus adapts scheduler cycle summaries to Prometheus metrics.
func (service *Service) ObserveFullSyncStatus(status scheduler.FullSyncStatus) {
	result := "success"
	if status.Failed {
		result = "failed"
	}

	service.fullSyncTotal.WithLabelValues(result).Inc()
	service.fullSyncDuration.Observe(max(0, status.FinishedAt.Sub(status.StartedAt).Seconds()))
	if status.SnapshotReady {
		service.discoveredGitLab.Set(float64(status.ProjectsFound))
		service.discoveredSonar.Set(float64(status.SonarProjects))
	}
}

// newRunID returns a random identifier; failure falls back to a non-sensitive timestamp token.
func newRunID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err == nil {
		return hex.EncodeToString(value[:])
	}

	return hex.EncodeToString([]byte(time.Now().UTC().Format("20060102150405.000000000"))) +
		"-" + strconv.FormatUint(fallbackRunID.Add(1), 16)
}

// bounded truncates externally sourced strings before they enter the run store.
func bounded(value string) string {
	value = strings.ToValidUTF8(value, "�")
	if len(value) > maxStoredTextSize {
		return strings.ToValidUTF8(value[:maxStoredTextSize], "")
	}

	return value
}

// boundedStrings copies and caps project keys recorded for one run.
func boundedStrings(values []string) []string {
	count := min(len(values), maxSonarProjects)
	result := make([]string, count)
	for index := range count {
		result[index] = bounded(values[index])
	}

	return result
}

// safeSource maps input to the supported source label set.
func safeSource(value string) string {
	switch value {
	case "ci", "manual", "scheduled":
		return value
	}
	return "ci"
}

// safeResult maps a reconciliation outcome to the supported result label set.
func safeResult(value reconcile.Status) reconcile.Status {
	switch value {
	case
		reconcile.StatusSuccess,
		reconcile.StatusPartial,
		reconcile.StatusFailed,
		reconcile.StatusSkipped:
		return value
	}

	return reconcile.StatusFailed
}

// safeResultLabel maps an observer outcome to the supported result label set.
func safeResultLabel(value string) string {
	switch value {
	case "success", "partial", "failed", "skipped":
		return value
	}

	return "failed"
}

// safeUpstream maps an adapter name to the supported upstream label set.
func safeUpstream(value string) string {
	if value == "gitlab" || value == "sonarqube" {
		return value
	}

	return ""
}

// safeStatusClass maps an HTTP outcome to the supported status class set.
func safeStatusClass(value string) string {
	switch value {
	case "2xx", "4xx", "5xx", "error":
		return value
	}

	return "error"
}

// safeOperation restricts upstream operation labels to the adapter's finite API.
func safeOperation(value string) string {
	allowed := map[string]struct{}{
		"validate job token":        {},
		"get project":               {},
		"list project members":      {},
		"get user":                  {},
		"get server version":        {},
		"search projects":           {},
		"get ALM binding":           {},
		"search users":              {},
		"search projects by query":  {},
		"read direct permissions":   {},
		"grant user permission":     {},
		"revoke user permission":    {},
		"update project visibility": {},
		"deactivate user":           {},
	}

	if _, ok := allowed[value]; ok {
		return value
	}

	return "other"
}

// safeAction maps permission actions to the supported action label set.
func safeAction(value string) string {
	switch value {
	case "grant", "revoke", "deactivate", "visibility":
		return value
	}

	return "other"
}

// safePermission maps permissions to the configured bounded label set.
func safePermission(value string) string {
	switch value {
	case
		"user",
		"codeviewer",
		"issueadmin",
		"securityhotspotadmin",
		"admin",
		"visibility",
		"deactivate":
		return value
	}

	return "other"
}
