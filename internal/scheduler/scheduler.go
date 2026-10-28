// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

// Package scheduler runs project reconciliation through a bounded worker pool.
package scheduler

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/woozymasta/guassp/internal/reconcile"
)

// Reconcile calls the wrapped reconciliation function.
func (function ReconcileFunc) Reconcile(ctx context.Context, projectID int64) reconcile.Result {
	return function(ctx, projectID)
}

// New creates a scheduler with a fixed worker count.
func New(
	workerCount int,
	reconciler Reconciler,
	logger zerolog.Logger,
	onResult ResultHandler,
) (*Scheduler, error) {
	if workerCount < 1 {
		return nil, errors.New("worker count must be positive")
	}
	if reconciler == nil {
		return nil, errors.New("reconciler is required")
	}

	scheduler := &Scheduler{
		reconciler:  reconciler,
		logger:      logger.With().Str("component", "scheduler").Logger(),
		onResult:    onResult,
		states:      make(map[int64]*projectState),
		changed:     make(chan struct{}, 1),
		done:        make(chan struct{}),
		workerCount: workerCount,
		accepting:   true,
	}
	scheduler.cond = sync.NewCond(&scheduler.mu)

	return scheduler, nil
}

// Start launches the fixed worker pool. A cancelled parent context cancels queued and running work.
func (scheduler *Scheduler) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("scheduler context is required")
	}

	scheduler.mu.Lock()
	if scheduler.started {
		scheduler.mu.Unlock()
		return errors.New("scheduler already started")
	}
	if scheduler.closing {
		scheduler.mu.Unlock()
		return errors.New("scheduler is closed")
	}

	runContext, cancel := context.WithCancel(ctx)
	scheduler.cancel = cancel
	scheduler.started = true
	scheduler.workerGroup.Add(scheduler.workerCount)
	scheduler.cond.Broadcast()
	scheduler.mu.Unlock()

	for range scheduler.workerCount {
		go scheduler.worker(runContext)
	}
	go func() {
		scheduler.workerGroup.Wait()
		scheduler.closeDone.Do(func() { close(scheduler.done) })
		cancel()
	}()
	go func() {
		<-runContext.Done()
		scheduler.Cancel()
	}()

	return nil
}

// Submit adds one project to the high- or low-priority queue.
func (scheduler *Scheduler) Submit(projectID int64, priority Priority, source string) (Submission, error) {
	if projectID < 1 {
		return Submission{}, errors.New("project ID must be positive")
	}
	if priority != PriorityLow && priority != PriorityHigh {
		return Submission{}, errors.New("unsupported priority")
	}

	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	if !scheduler.accepting || scheduler.closing {
		return Submission{}, nil
	}

	if state, exists := scheduler.states[projectID]; exists {
		if state.phase == phaseRunning {
			if !state.dirty || priority > state.dirtyPriority {
				state.dirtyPriority = priority
				state.dirtySource = source
			}

			state.dirty = true
			scheduler.logSubmission(projectID, priority, source, true, "running")
			return Submission{Accepted: true, Coalesced: true}, nil
		}

		if priority > state.priority {
			scheduler.removeQueued(projectID, state.priority)
			state.priority = priority
			state.source = source
			scheduler.appendQueued(projectID, priority)
		}

		scheduler.logSubmission(projectID, priority, source, true, "queued")
		return Submission{Accepted: true, Coalesced: true}, nil
	}

	scheduler.states[projectID] = &projectState{
		phase:    phaseQueued,
		priority: priority,
		source:   source,
		queuedAt: time.Now(),
	}

	scheduler.appendQueued(projectID, priority)
	scheduler.cond.Signal()
	scheduler.notifyChanged()
	scheduler.logSubmission(projectID, priority, source, false, "queued")

	return Submission{Accepted: true}, nil
}

// logSubmission records accepted work without inspecting scheduler state beyond the request.
func (scheduler *Scheduler) logSubmission(projectID int64, priority Priority, source string, coalesced bool, phase string) {
	event := scheduler.logger.Debug()
	if !event.Enabled() {
		return
	}

	event.Str("operation", "submit reconciliation").
		Int64("gitlab_project_id", projectID).
		Str("source", source).
		Str("priority", priority.String()).
		Str("phase", phase).
		Bool("coalesced", coalesced).
		Msg("reconciliation accepted")
}

// StopAccepting rejects new submissions while allowing accepted work to finish.
func (scheduler *Scheduler) StopAccepting() {
	scheduler.mu.Lock()
	scheduler.accepting = false
	scheduler.mu.Unlock()
}

// Drain stops submissions and waits for queued and running work up to grace.
func (scheduler *Scheduler) Drain(grace time.Duration) {
	scheduler.StopAccepting()
	deadline := time.NewTimer(grace)
	defer deadline.Stop()

	for {
		scheduler.mu.Lock()
		if len(scheduler.states) == 0 {
			scheduler.closing = true
			scheduler.cond.Broadcast()
			started := scheduler.started
			scheduler.mu.Unlock()
			if !started {
				scheduler.closeDone.Do(func() { close(scheduler.done) })
			}

			<-scheduler.done
			return
		}

		started := scheduler.started
		changed := scheduler.changed
		scheduler.mu.Unlock()

		if !started || grace <= 0 {
			scheduler.Cancel()
			<-scheduler.done
			return
		}

		select {
		case <-changed:
		case <-deadline.C:
			scheduler.Cancel()
			<-scheduler.done
			return

		case <-scheduler.done:
			return
		}
	}
}

// Cancel discards queued work and cancels active reconciliations.
func (scheduler *Scheduler) Cancel() {
	scheduler.mu.Lock()
	scheduler.accepting = false
	scheduler.closing = true
	scheduler.highQueue = nil
	scheduler.lowQueue = nil
	for projectID, state := range scheduler.states {
		if state.phase == phaseRunning {
			state.dirty = false
			continue
		}

		delete(scheduler.states, projectID)
	}

	cancel := scheduler.cancel
	started := scheduler.started
	scheduler.cond.Broadcast()
	scheduler.notifyChanged()
	scheduler.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if !started {
		scheduler.closeDone.Do(func() { close(scheduler.done) })
	}
}

// Done returns a channel closed after all workers exit.
func (scheduler *Scheduler) Done() <-chan struct{} {
	return scheduler.done
}

// Stats returns a snapshot of queue and in-flight counts.
func (scheduler *Scheduler) Stats() Stats {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()

	stats := Stats{HighQueue: len(scheduler.highQueue), LowQueue: len(scheduler.lowQueue)}
	for _, state := range scheduler.states {
		if state.phase == phaseRunning {
			stats.Inflight++
		}
	}

	return stats
}
