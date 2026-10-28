// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/woozymasta/guassp/internal/reconcile"
)

// Priority orders project work. High-priority work is always selected first.
type Priority uint8

const (
	// PriorityLow is intended for scheduled background reconciliation.
	PriorityLow Priority = iota
	// PriorityHigh is intended for CI and manual reconciliation requests.
	PriorityHigh
)

// String returns a readable priority name for logs and diagnostics.
func (priority Priority) String() string {
	switch priority {
	case PriorityLow:
		return "low"

	case PriorityHigh:
		return "high"

	default:
		return fmt.Sprintf("unknown(%d)", priority)
	}
}

// Reconciler executes one GitLab project reconciliation.
type Reconciler interface {
	// Reconcile executes one project run with a cancellable context.
	Reconcile(context.Context, int64) reconcile.Result
}

// ReconcileFunc adapts a function to the Reconciler interface.
type ReconcileFunc func(context.Context, int64) reconcile.Result

// Run records the result and timing of one reconciliation attempt.
type Run struct {
	// QueuedAt is the time this execution entered the scheduler.
	QueuedAt time.Time
	// StartedAt is the time the worker began the reconciliation.
	StartedAt time.Time
	// FinishedAt is the time the reconciliation returned.
	FinishedAt time.Time
	// Source identifies the submission source, such as ci, manual, or scheduled.
	Source string
	// Result contains the reconciler outcome or a sanitized panic result.
	Result reconcile.Result
	// ProjectID identifies the GitLab project.
	ProjectID int64
	// Priority is the priority used for this execution.
	Priority Priority
}

// ResultHandler receives completed reconciliation runs.
type ResultHandler func(Run)

// Submission describes whether a project was accepted and coalesced.
type Submission struct {
	// Accepted is false when shutdown has stopped new work.
	Accepted bool
	// Coalesced is true when this request joined queued or running work.
	Coalesced bool
}

// Scheduler holds bounded project queues and a fixed number of workers.
type Scheduler struct {
	logger      zerolog.Logger
	reconciler  Reconciler
	cond        *sync.Cond
	onResult    ResultHandler
	states      map[int64]*projectState
	changed     chan struct{}
	done        chan struct{}
	cancel      context.CancelFunc
	highQueue   []int64
	lowQueue    []int64
	workerGroup sync.WaitGroup
	workerCount int
	closeDone   sync.Once
	mu          sync.Mutex
	started     bool
	accepting   bool
	closing     bool
}

// Stats reports bounded scheduler queue and worker counts.
type Stats struct {
	// HighQueue is the number of queued high-priority projects.
	HighQueue int `json:"high_queue"`
	// LowQueue is the number of queued low-priority projects.
	LowQueue int `json:"low_queue"`
	// Inflight is the number of projects currently being reconciled.
	Inflight int `json:"inflight"`
}

// projectState tracks the single queued or running entry for a project.
type projectState struct {
	queuedAt      time.Time
	source        string
	dirtySource   string
	phase         projectPhase
	priority      Priority
	dirty         bool
	dirtyPriority Priority
}

// projectPhase identifies whether a project is queued or being reconciled.
type projectPhase uint8

const (
	// phaseQueued means the project is present in one priority queue.
	phaseQueued projectPhase = iota
	// phaseRunning means one worker currently reconciles the project.
	phaseRunning
)

// queuedProject contains the scheduling metadata copied when a worker takes a job.
type queuedProject struct {
	queuedAt  time.Time
	source    string
	projectID int64
	priority  Priority
}
