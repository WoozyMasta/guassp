// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package scheduler

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/woozymasta/guassp/internal/config"
	"github.com/woozymasta/guassp/internal/discovery"
)

const preflightRetryDelay = 30 * time.Second

// PreflightChecker validates upstream access before bulk discovery starts.
type PreflightChecker interface {
	// Check verifies that required upstream API operations are available.
	Check(context.Context) error
}

// BindingRefresher refreshes and publishes the SonarQube binding index.
type BindingRefresher interface {
	// Refresh returns the complete binding snapshot after a successful refresh.
	Refresh(context.Context) (*discovery.Snapshot, error)
}

// ProjectSubmitter queues projects for reconciliation.
type ProjectSubmitter interface {
	// Submit queues one project at the requested priority.
	Submit(int64, Priority, string) (Submission, error)
}

// FullSyncObserver receives completed discovery cycle summaries.
type FullSyncObserver interface {
	// ObserveFullSyncStatus records a completed discovery cycle.
	ObserveFullSyncStatus(FullSyncStatus)
}

// FullSyncStatus describes the most recent discovery and enqueue cycle.
type FullSyncStatus struct {
	// NextAt is the next local scheduled cycle, when daily scheduling is enabled.
	NextAt time.Time `json:"next_at,omitzero" yaml:"next_at,omitempty"`
	// StartedAt is when the most recent cycle began.
	StartedAt time.Time `json:"started_at,omitzero" yaml:"started_at,omitempty"`
	// FinishedAt is when the most recent cycle ended.
	FinishedAt time.Time `json:"finished_at,omitzero" yaml:"finished_at,omitempty"`
	// ProjectsFound is the number of unique GitLab projects in the snapshot.
	ProjectsFound int `json:"projects_found" yaml:"projects_found"`
	// SonarProjects is the number of bound SonarQube projects in the snapshot.
	SonarProjects int `json:"sonar_projects" yaml:"sonar_projects"`
	// Submitted is the number of accepted low-priority submissions.
	Submitted int `json:"submitted" yaml:"submitted"`
	// Coalesced is the number of accepted submissions joined with existing work.
	Coalesced int `json:"coalesced" yaml:"coalesced"`
	// ErrorCount is the number of discovery or submission failures.
	ErrorCount int `json:"error_count" yaml:"error_count"`
	// SnapshotReady reports that a complete binding snapshot was loaded.
	SnapshotReady bool `json:"snapshot_ready" yaml:"snapshot_ready"`
	// Running reports whether a discovery and enqueue cycle is active.
	Running bool `json:"running" yaml:"running"`
	// Queued reports whether a manual cycle is waiting to start.
	Queued bool `json:"queued" yaml:"queued"`
	// Failed reports whether discovery or any project submission failed.
	Failed bool `json:"failed" yaml:"failed"`
}

// FullSync runs scheduled and explicitly requested discovery cycles.
type FullSync struct {
	discovery    BindingRefresher
	scheduler    ProjectSubmitter
	preflight    PreflightChecker
	logger       zerolog.Logger
	schedule     config.DailyTime
	observer     FullSyncObserver
	readiness    func(bool)
	now          func() time.Time
	newTimer     func(time.Duration) dailyTimer
	manual       chan struct{}
	done         chan struct{}
	cancel       context.CancelFunc
	status       FullSyncStatus
	manualQueued bool
	mu           sync.Mutex
	started      bool
}

// dailyTimer is the timer surface needed by the full-sync loop.
type dailyTimer interface {
	// C returns the timer firing channel.
	C() <-chan time.Time
	// Stop stops the timer and reports whether it was active.
	Stop() bool
}

// systemDailyTimer adapts time.Timer to dailyTimer.
type systemDailyTimer struct {
	timer *time.Timer
}

// C returns the underlying timer channel.
func (timer systemDailyTimer) C() <-chan time.Time {
	return timer.timer.C
}

// Stop stops the underlying timer.
func (timer systemDailyTimer) Stop() bool {
	return timer.timer.Stop()
}

// NewFullSync creates a runner that performs scheduled and requested cycles.
func NewFullSync(
	schedule config.DailyTime,
	discovery BindingRefresher,
	projectScheduler ProjectSubmitter,
	logger zerolog.Logger,
) (*FullSync, error) {
	return newFullSync(
		schedule,
		discovery,
		projectScheduler,
		logger,
		time.Now,
		func(delay time.Duration) dailyTimer {
			return systemDailyTimer{timer: time.NewTimer(delay)}
		},
	)
}

// newFullSync creates a runner with injectable time sources for deterministic tests.
func newFullSync(
	schedule config.DailyTime,
	discovery BindingRefresher,
	projectScheduler ProjectSubmitter,
	logger zerolog.Logger,
	now func() time.Time,
	newTimer func(time.Duration) dailyTimer,
) (*FullSync, error) {
	if discovery == nil || projectScheduler == nil {
		return nil, errors.New("binding discovery and project scheduler are required")
	}
	if now == nil || newTimer == nil {
		return nil, errors.New("full-sync clock and timer factory are required")
	}

	if schedule.Enabled() {
		if _, err := time.Parse("15:04", string(schedule)); err != nil {
			return nil, fmt.Errorf("invalid full-sync time: %w", err)
		}
	}

	return &FullSync{
		discovery: discovery,
		scheduler: projectScheduler,
		logger:    logger.With().Str("component", "full_sync").Logger(),
		schedule:  schedule,
		now:       now,
		newTimer:  newTimer,
		manual:    make(chan struct{}, 1),
	}, nil
}

// Start launches the preflight and discovery loop.
func (fullSync *FullSync) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("full-sync context is required")
	}

	fullSync.mu.Lock()
	defer fullSync.mu.Unlock()
	if fullSync.started {
		return errors.New("full-sync runner already started")
	}

	fullSync.started = true
	runContext, cancel := context.WithCancel(ctx)
	fullSync.cancel = cancel
	fullSync.done = make(chan struct{})
	go fullSync.run(runContext)

	return nil
}

// Trigger queues a manual full-sync cycle unless one is already queued or running.
func (fullSync *FullSync) Trigger() bool {
	fullSync.mu.Lock()
	defer fullSync.mu.Unlock()
	if !fullSync.started || fullSync.status.Running || fullSync.manualQueued {
		return false
	}

	fullSync.manualQueued = true
	select {
	case fullSync.manual <- struct{}{}:
		return true

	default:
		fullSync.manualQueued = false
		return false
	}
}

// Stop cancels an active discovery cycle and waits for the timer loop to exit.
func (fullSync *FullSync) Stop() {
	fullSync.mu.Lock()
	cancel := fullSync.cancel
	done := fullSync.done
	fullSync.mu.Unlock()
	if cancel == nil {
		return
	}

	cancel()
	<-done
}

// Status returns a copy of the latest discovery-cycle status.
func (fullSync *FullSync) Status() FullSyncStatus {
	fullSync.mu.Lock()
	status := fullSync.status
	status.Queued = fullSync.manualQueued
	fullSync.mu.Unlock()
	if fullSync.schedule.Enabled() {
		status.NextAt = nextFullSync(fullSync.schedule, fullSync.now())
	}

	return status
}

// SetObserver configures a cycle observer before the runner starts.
func (fullSync *FullSync) SetObserver(observer FullSyncObserver) {
	fullSync.mu.Lock()
	fullSync.observer = observer
	fullSync.mu.Unlock()
}

// SetPreflight configures upstream checks that run before discovery.
func (fullSync *FullSync) SetPreflight(preflight PreflightChecker) {
	fullSync.mu.Lock()
	fullSync.preflight = preflight
	fullSync.mu.Unlock()
}

// SetReadinessHandler configures readiness updates after preflight outcomes.
func (fullSync *FullSync) SetReadinessHandler(handler func(bool)) {
	fullSync.mu.Lock()
	fullSync.readiness = handler
	fullSync.mu.Unlock()
}

// run performs scheduled and explicitly requested discovery cycles.
func (fullSync *FullSync) run(ctx context.Context) {
	defer close(fullSync.done)
	if !fullSync.waitForPreflight(ctx) {
		return
	}

	var timer dailyTimer
	var scheduled <-chan time.Time
	if fullSync.schedule.Enabled() {
		now := fullSync.now()
		timer = fullSync.newTimer(nextFullSync(fullSync.schedule, now).Sub(now))
		scheduled = timer.C()
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for ctx.Err() == nil {
		select {
		case <-fullSync.manual:
			if !fullSync.waitForPreflight(ctx) {
				return
			}
			fullSync.runCycle(ctx, "manual_full_sync")

		case <-scheduled:
			if timer != nil {
				timer.Stop()
				timer = nil
				scheduled = nil
			}
			if fullSync.waitForPreflight(ctx) && ctx.Err() == nil {
				fullSync.runCycle(ctx, "scheduled")
			}
			if fullSync.schedule.Enabled() && ctx.Err() == nil {
				now := fullSync.now()
				timer = fullSync.newTimer(nextFullSync(fullSync.schedule, now).Sub(now))
				scheduled = timer.C()
			}

		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		}
	}
}

// waitForPreflight retries failed checks while keeping the service unready.
func (fullSync *FullSync) waitForPreflight(ctx context.Context) bool {
	for ctx.Err() == nil {
		fullSync.mu.Lock()
		preflight := fullSync.preflight
		readiness := fullSync.readiness
		fullSync.mu.Unlock()

		if preflight == nil {
			if readiness != nil {
				readiness(true)
			}
			return true
		}

		err := preflight.Check(ctx)
		if err == nil {
			if readiness != nil {
				readiness(true)
			}
			fullSync.logger.Info().Msg("upstream preflight checks passed")
			return true
		}
		if readiness != nil {
			readiness(false)
		}
		fullSync.logger.Error().Err(err).
			Dur("retry_in", preflightRetryDelay).
			Msg("upstream preflight checks failed; discovery is deferred")

		timer := fullSync.newTimer(preflightRetryDelay)
		select {
		case <-timer.C():
			timer.Stop()
		case <-ctx.Done():
			timer.Stop()
			return false
		}
	}

	return false
}

// runCycle serializes discovery and submits every unique project at low priority.
func (fullSync *FullSync) runCycle(ctx context.Context, trigger string) bool {
	fullSync.mu.Lock()
	if fullSync.status.Running || ctx.Err() != nil {
		fullSync.mu.Unlock()
		return false
	}

	if trigger == "manual_full_sync" {
		fullSync.manualQueued = false
	}
	startedAt := fullSync.now()
	fullSync.status = FullSyncStatus{Running: true, StartedAt: startedAt}
	fullSync.mu.Unlock()
	if event := fullSync.logger.Trace(); event.Enabled() {
		event.Str("operation", "refresh project bindings").
			Str("trigger", trigger).
			Time("started_at", startedAt).
			Msg("discovery cycle started")
	}

	status := FullSyncStatus{StartedAt: startedAt}
	snapshot, err := fullSync.discovery.Refresh(ctx)
	if err != nil {
		status.Failed = true
		status.ErrorCount++
		fullSync.logger.Warn().
			Str("operation", "refresh project bindings").
			Str("trigger", trigger).
			Str("result", "failed").
			Msg("discovery cycle failed")
		fullSync.finishCycle(status, trigger)
		return true
	}

	if snapshot == nil {
		status.Failed = true
		status.ErrorCount++
		fullSync.logger.Error().
			Str("operation", "refresh project bindings").
			Str("trigger", trigger).
			Str("result", "failed").
			Msg("discovery cycle returned an empty snapshot")
		fullSync.finishCycle(status, trigger)

		return true
	}

	projectIDs := snapshot.GitLabProjectIDs()
	status.SnapshotReady = true
	status.ProjectsFound = len(projectIDs)
	for _, warning := range snapshot.Warnings() {
		fullSync.logger.Warn().
			Str("operation", "refresh project bindings").
			Str("sonar_project_key", warning.ProjectKey).
			Str("reason", warning.Reason).
			Msg("SonarQube project binding was omitted or retained as a stale hint")
	}
	for _, projectID := range projectIDs {
		status.SonarProjects += len(snapshot.Projects(projectID))
	}

	for _, projectID := range projectIDs {
		submission, submitErr := fullSync.scheduler.Submit(projectID, PriorityLow, trigger)
		if submitErr != nil || !submission.Accepted {
			status.Failed = true
			status.ErrorCount++
			continue
		}

		status.Submitted++
		if submission.Coalesced {
			status.Coalesced++
		}
	}

	fullSync.finishCycle(status, trigger)
	return true
}

// finishCycle publishes status and logs a bounded summary without raw errors.
func (fullSync *FullSync) finishCycle(status FullSyncStatus, trigger string) {
	status.Running = false
	status.FinishedAt = fullSync.now()
	fullSync.mu.Lock()
	fullSync.status = status
	observer := fullSync.observer
	fullSync.mu.Unlock()
	if observer != nil {
		observer.ObserveFullSyncStatus(status)
	}
	if status.Failed {
		fullSync.logger.Warn().
			Str("operation", "refresh project bindings").
			Str("trigger", trigger).
			Str("result", "failed").
			Dur("duration", status.FinishedAt.Sub(status.StartedAt)).
			Int("projects_found", status.ProjectsFound).
			Int("submitted", status.Submitted).
			Int("errors", status.ErrorCount).
			Msg("discovery cycle completed with errors")
		return
	}

	fullSync.logger.Info().
		Str("operation", "refresh project bindings").
		Str("trigger", trigger).
		Str("result", "success").
		Dur("duration", status.FinishedAt.Sub(status.StartedAt)).
		Int("projects_found", status.ProjectsFound).
		Int("submitted", status.Submitted).
		Int("coalesced", status.Coalesced).
		Msg("discovery cycle completed")
}

// nextFullSync returns the next local occurrence strictly after now.
func nextFullSync(schedule config.DailyTime, now time.Time) time.Time {
	if !schedule.Enabled() {
		return time.Time{}
	}

	hour, minute := schedule.HourMinute()
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location())
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}

	return next
}
