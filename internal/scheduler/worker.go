// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package scheduler

import (
	"context"
	"slices"
	"time"

	"github.com/woozymasta/guassp/internal/reconcile"
)

// worker processes projects until the scheduler closes.
func (scheduler *Scheduler) worker(ctx context.Context) {
	defer scheduler.workerGroup.Done()
	for {
		job, ok := scheduler.next(ctx)
		if !ok {
			return
		}
		run := scheduler.execute(ctx, job)
		scheduler.record(run)
		scheduler.complete(job.projectID)
	}
}

// next waits for work and atomically marks its project as running.
func (scheduler *Scheduler) next(ctx context.Context) (queuedProject, bool) {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()

	for len(scheduler.highQueue) == 0 && len(scheduler.lowQueue) == 0 && !scheduler.closing && ctx.Err() == nil {
		scheduler.cond.Wait()
	}
	if scheduler.closing || ctx.Err() != nil {
		return queuedProject{}, false
	}

	var projectID int64
	var priority Priority
	if len(scheduler.highQueue) > 0 {
		projectID, scheduler.highQueue = scheduler.highQueue[0], scheduler.highQueue[1:]
		priority = PriorityHigh
	} else {
		projectID, scheduler.lowQueue = scheduler.lowQueue[0], scheduler.lowQueue[1:]
		priority = PriorityLow
	}

	state := scheduler.states[projectID]
	state.phase = phaseRunning
	state.priority = priority
	scheduler.notifyChanged()

	return queuedProject{
		queuedAt:  state.queuedAt,
		projectID: projectID,
		priority:  priority,
		source:    state.source,
	}, true
}

// execute isolates reconciliation panics and creates one run record.
func (scheduler *Scheduler) execute(ctx context.Context, job queuedProject) (run Run) {
	run = Run{
		QueuedAt:  job.queuedAt,
		ProjectID: job.projectID,
		Priority:  job.priority,
		Source:    job.source,
		StartedAt: time.Now(),
	}

	if event := scheduler.logger.Trace(); event.Enabled() {
		event.Str("operation", "execute reconciliation").
			Int64("gitlab_project_id", job.projectID).
			Str("source", job.source).
			Str("priority", job.priority.String()).
			Dur("queue_duration", run.StartedAt.Sub(job.queuedAt)).
			Msg("worker started reconciliation")
	}

	defer func() {
		run.FinishedAt = time.Now()
		if recovered := recover(); recovered != nil {
			run.Result = reconcile.Result{
				ProjectID: job.projectID,
				Status:    reconcile.StatusFailed,
				Errors:    []string{"reconciliation panicked"},
			}
			scheduler.logger.Error().
				Str("operation", "execute reconciliation").
				Int64("gitlab_project_id", job.projectID).
				Msg("reconciliation panicked")
		}
	}()

	run.Result = scheduler.reconciler.Reconcile(ctx, job.projectID)
	return run
}

// complete moves a dirty run back to one queued rerun or removes idle state.
func (scheduler *Scheduler) complete(projectID int64) {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	state, exists := scheduler.states[projectID]
	if !exists {
		return
	}

	if scheduler.closing {
		delete(scheduler.states, projectID)
		scheduler.notifyChanged()
		return
	}

	if state.dirty {
		state.phase = phaseQueued
		state.priority = state.dirtyPriority
		state.source = state.dirtySource
		state.queuedAt = time.Now()
		state.dirty = false
		state.dirtyPriority = PriorityLow
		state.dirtySource = ""
		scheduler.appendQueued(projectID, state.priority)
		scheduler.cond.Signal()
	} else {
		delete(scheduler.states, projectID)
	}

	scheduler.notifyChanged()
}

// record logs and forwards one completed run without exposing panic details.
func (scheduler *Scheduler) record(run Run) {
	if event := scheduler.logger.Debug(); event.Enabled() {
		event.Str("operation", "execute reconciliation").
			Int64("gitlab_project_id", run.ProjectID).
			Str("source", run.Source).
			Str("result", string(run.Result.Status)).
			Dur("duration", run.FinishedAt.Sub(run.StartedAt)).
			Int("grants", run.Result.Counts.Grants).
			Int("revokes", run.Result.Counts.Revokes).
			Int("unknown_user_states", run.Result.Counts.UnknownUserStates).
			Int("errors", run.Result.Counts.Errors).
			Msg("reconciliation run details")
	}
	if run.Result.Status == reconcile.StatusFailed || run.Result.Status == reconcile.StatusPartial {
		scheduler.logger.Warn().
			Str("operation", "execute reconciliation").
			Int64("gitlab_project_id", run.ProjectID).
			Str("source", run.Source).
			Str("status", string(run.Result.Status)).
			Str("result", string(run.Result.Status)).
			Dur("duration", run.FinishedAt.Sub(run.StartedAt)).
			Msg("project reconciliation completed with issues")
	} else {
		scheduler.logger.Info().
			Str("operation", "execute reconciliation").
			Int64("gitlab_project_id", run.ProjectID).
			Str("source", run.Source).
			Str("status", string(run.Result.Status)).
			Str("result", string(run.Result.Status)).
			Dur("duration", run.FinishedAt.Sub(run.StartedAt)).
			Msg("project reconciliation completed")
	}
	if scheduler.onResult == nil {
		return
	}

	defer func() {
		if recover() != nil {
			scheduler.logger.Error().
				Str("operation", "record reconciliation result").
				Int64("gitlab_project_id", run.ProjectID).
				Msg("reconciliation result handler panicked")
		}
	}()

	scheduler.onResult(run)
}

// appendQueued adds a project to the matching FIFO queue.
func (scheduler *Scheduler) appendQueued(projectID int64, priority Priority) {
	if priority == PriorityHigh {
		scheduler.highQueue = append(scheduler.highQueue, projectID)
		return
	}

	scheduler.lowQueue = append(scheduler.lowQueue, projectID)
}

// removeQueued removes one project from the queue selected by its current priority.
func (scheduler *Scheduler) removeQueued(projectID int64, priority Priority) {
	queue := &scheduler.lowQueue
	if priority == PriorityHigh {
		queue = &scheduler.highQueue
	}
	if index := slices.Index(*queue, projectID); index >= 0 {
		*queue = slices.Delete(*queue, index, index+1)
	}
}

// notifyChanged wakes drain waiters after a queued or running state changes.
func (scheduler *Scheduler) notifyChanged() {
	select {
	case scheduler.changed <- struct{}{}:
	default:
	}
}
