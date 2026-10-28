// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package scheduler

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/woozymasta/guassp/internal/reconcile"
)

type fakeReconciler struct {
	mu         sync.Mutex
	callCounts map[int64]int
	active     int
	maxActive  int
	started    chan int64
	result     func(context.Context, int64, int)
}

// Reconcile records one fake call and runs its configured behavior.
func (reconciler *fakeReconciler) Reconcile(ctx context.Context, projectID int64) reconcile.Result {
	reconciler.mu.Lock()
	if reconciler.callCounts == nil {
		reconciler.callCounts = make(map[int64]int)
	}

	reconciler.callCounts[projectID]++
	call := reconciler.callCounts[projectID]
	reconciler.active++
	if reconciler.active > reconciler.maxActive {
		reconciler.maxActive = reconciler.active
	}
	reconciler.mu.Unlock()
	defer func() {
		reconciler.mu.Lock()
		reconciler.active--
		reconciler.mu.Unlock()
	}()

	if reconciler.started != nil {
		reconciler.started <- projectID
	}
	if reconciler.result != nil {
		reconciler.result(ctx, projectID, call)
	}

	return reconcile.Result{ProjectID: projectID, Status: reconcile.StatusSuccess}
}

func TestSchedulerCoalescesDuplicateQueuedSubmissions(t *testing.T) {
	reconciler := &fakeReconciler{}
	runs := make(chan Run, 4)
	scheduler := newTestScheduler(t, 1, reconciler, func(run Run) { runs <- run })

	first := submit(t, scheduler, 10, PriorityLow, "scheduled")
	second := submit(t, scheduler, 10, PriorityLow, "scheduled")
	third := submit(t, scheduler, 10, PriorityHigh, "ci")
	if !first.Accepted ||
		first.Coalesced ||
		!second.Accepted ||
		!second.Coalesced ||
		!third.Accepted ||
		!third.Coalesced {
		t.Fatalf("submissions = %+v, %+v, %+v", first, second, third)
	}
	if err := scheduler.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if run := receiveRun(t, runs); run.ProjectID != 10 || run.Priority != PriorityHigh || run.Source != "ci" {
		t.Fatalf("run = %+v", run)
	}

	scheduler.Drain(time.Second)
	if got := reconciler.calls(10); got != 1 {
		t.Fatalf("reconcile calls = %d, want 1", got)
	}
}

func TestPriorityString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		priority Priority
		want     string
	}{
		{priority: PriorityLow, want: "low"},
		{priority: PriorityHigh, want: "high"},
		{priority: Priority(2), want: "unknown(2)"},
	}
	for _, test := range tests {
		t.Run(test.want, func(t *testing.T) {
			t.Parallel()
			if got := test.priority.String(); got != test.want {
				t.Fatalf("Priority(%d).String() = %q, want %q", test.priority, got, test.want)
			}
		})
	}
}

func TestSchedulerPromotesQueuedWorkAndPrefersHighPriority(t *testing.T) {
	reconciler := &fakeReconciler{}
	runs := make(chan Run, 4)
	scheduler := newTestScheduler(t, 1, reconciler, func(run Run) { runs <- run })
	submit(t, scheduler, 10, PriorityLow, "scheduled")
	submit(t, scheduler, 20, PriorityLow, "scheduled")
	submit(t, scheduler, 10, PriorityHigh, "manual")

	if err := scheduler.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	first := receiveRun(t, runs)
	second := receiveRun(t, runs)
	if first.ProjectID != 10 || first.Priority != PriorityHigh || first.Source != "manual" {
		t.Fatalf("first run = %+v", first)
	}
	if second.ProjectID != 20 || second.Priority != PriorityLow {
		t.Fatalf("second run = %+v", second)
	}
	scheduler.Drain(time.Second)
}

func TestSchedulerCoalescesRunningSubmissionsIntoOneHighRerun(t *testing.T) {
	started := make(chan int64, 4)
	release := make(chan struct{})
	reconciler := &fakeReconciler{
		started: started,
		result: func(_ context.Context, _ int64, call int) {
			if call == 1 {
				<-release
			}
		},
	}
	runs := make(chan Run, 4)
	scheduler := newTestScheduler(t, 2, reconciler, func(run Run) { runs <- run })
	if err := scheduler.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	submit(t, scheduler, 10, PriorityLow, "scheduled")
	if got := receiveProject(t, started); got != 10 {
		t.Fatalf("started project = %d, want 10", got)
	}
	for range 100 {
		submit(t, scheduler, 10, PriorityLow, "scheduled")
	}
	submit(t, scheduler, 10, PriorityHigh, "ci")
	close(release)

	first := receiveRun(t, runs)
	second := receiveRun(t, runs)
	if first.Priority != PriorityLow || second.Priority != PriorityHigh || second.Source != "ci" {
		t.Fatalf("runs = %+v, %+v", first, second)
	}
	scheduler.Drain(time.Second)
	if got := reconciler.calls(10); got != 2 {
		t.Fatalf("reconcile calls = %d, want 2", got)
	}
	if got := reconciler.maximumActive(); got != 1 {
		t.Fatalf("same-project concurrent runs = %d, want 1", got)
	}
}

func TestSchedulerRunsDifferentProjectsUpToWorkerCount(t *testing.T) {
	started := make(chan int64, 4)
	release := make(chan struct{}, 4)
	reconciler := &fakeReconciler{
		started: started,
		result:  func(context.Context, int64, int) { <-release },
	}
	runs := make(chan Run, 4)
	scheduler := newTestScheduler(t, 2, reconciler, func(run Run) { runs <- run })
	if err := scheduler.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	for projectID := int64(1); projectID <= 3; projectID++ {
		submit(t, scheduler, projectID, PriorityHigh, "ci")
	}

	startedProjects := []int64{receiveProject(t, started), receiveProject(t, started)}
	slices.Sort(startedProjects)
	if !slices.Equal(startedProjects, []int64{1, 2}) {
		t.Fatalf("concurrent projects = %v, want [1 2]", startedProjects)
	}
	if got := reconciler.maximumActive(); got != 2 {
		t.Fatalf("maximum active runs = %d, want 2", got)
	}
	release <- struct{}{}
	if got := receiveProject(t, started); got != 3 {
		t.Fatalf("third project = %d, want 3", got)
	}
	release <- struct{}{}
	release <- struct{}{}
	for range 3 {
		receiveRun(t, runs)
	}
	scheduler.Drain(time.Second)
}

func TestSchedulerDrainCancelsBlockedReconcile(t *testing.T) {
	started := make(chan int64, 1)
	reconciler := &fakeReconciler{
		started: started,
		result: func(ctx context.Context, _ int64, _ int) {
			<-ctx.Done()
		},
	}
	scheduler := newTestScheduler(t, 1, reconciler, nil)
	if err := scheduler.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	submit(t, scheduler, 10, PriorityHigh, "ci")
	receiveProject(t, started)
	scheduler.Drain(0)
	select {
	case <-scheduler.Done():
	default:
		t.Fatal("scheduler did not stop after cancellation")
	}
	submission, err := scheduler.Submit(20, PriorityHigh, "ci")
	if err != nil || submission.Accepted {
		t.Fatalf("submission after shutdown = %+v, %v", submission, err)
	}
}

func TestSchedulerRecoversPanicAndContinuesWorkers(t *testing.T) {
	reconciler := &fakeReconciler{result: func(_ context.Context, projectID int64, _ int) {
		if projectID == 10 {
			panic("secret token=hidden")
		}
	}}
	runs := make(chan Run, 4)
	scheduler := newTestScheduler(t, 1, reconciler, func(run Run) { runs <- run })
	submit(t, scheduler, 10, PriorityHigh, "ci")
	submit(t, scheduler, 20, PriorityHigh, "ci")
	if err := scheduler.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	failed := receiveRun(t, runs)
	succeeded := receiveRun(t, runs)
	if failed.Result.Status != reconcile.StatusFailed ||
		!slices.Equal(failed.Result.Errors, []string{"reconciliation panicked"}) {
		t.Fatalf("panic result = %+v", failed.Result)
	}
	if succeeded.ProjectID != 20 || succeeded.Result.Status != reconcile.StatusSuccess {
		t.Fatalf("run after panic = %+v", succeeded)
	}
	if strings.Contains(strings.Join(failed.Result.Errors, " "), "hidden") {
		t.Fatal("panic details leaked")
	}
	scheduler.Drain(time.Second)
}

func TestSchedulerRejectsInvalidConfigurationAndSubmissions(t *testing.T) {
	if _, err := New(0, ReconcileFunc(func(context.Context, int64) reconcile.Result { return reconcile.Result{} }),
		zerolog.Nop(), nil); err == nil {
		t.Fatal("New accepted zero workers")
	}
	if _, err := New(1, nil, zerolog.Nop(), nil); err == nil {
		t.Fatal("New accepted a nil reconciler")
	}
	scheduler := newTestScheduler(t, 1, &fakeReconciler{}, nil)
	if _, err := scheduler.Submit(0, PriorityHigh, "ci"); err == nil {
		t.Fatal("Submit accepted a nonpositive project ID")
	}
	if _, err := scheduler.Submit(1, Priority(2), "ci"); err == nil {
		t.Fatal("Submit accepted an unsupported priority")
	}
	scheduler.Cancel()
}

// newTestScheduler constructs a scheduler and registers cancellation cleanup.
func newTestScheduler(
	t *testing.T,
	workers int,
	reconciler Reconciler,
	handler ResultHandler,
) *Scheduler {
	t.Helper()
	scheduler, err := New(workers, reconciler, zerolog.Nop(), handler)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		scheduler.Cancel()
		select {
		case <-scheduler.Done():
		case <-time.After(time.Second):
			t.Error("scheduler did not stop during cleanup")
		}
	})

	return scheduler
}

// submit adds a test project and fails immediately on an invalid request.
func submit(t *testing.T, scheduler *Scheduler, projectID int64, priority Priority, source string) Submission {
	t.Helper()
	submission, err := scheduler.Submit(projectID, priority, source)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	return submission
}

// receiveProject waits for a specific fake call to enter execution.
func receiveProject(t *testing.T, projects <-chan int64) int64 {
	t.Helper()
	select {
	case projectID := <-projects:
		return projectID
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for project execution")
		return 0
	}
}

// receiveRun waits for a completed scheduler result.
func receiveRun(t *testing.T, runs <-chan Run) Run {
	t.Helper()
	select {
	case run := <-runs:
		return run
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for reconciliation result")
		return Run{}
	}
}

// calls reports how many times a project entered the fake reconciler.
func (reconciler *fakeReconciler) calls(projectID int64) int {
	reconciler.mu.Lock()
	defer reconciler.mu.Unlock()
	return reconciler.callCounts[projectID]
}

// maximumActive reports the highest number of concurrent fake calls.
func (reconciler *fakeReconciler) maximumActive() int {
	reconciler.mu.Lock()
	defer reconciler.mu.Unlock()
	return reconciler.maxActive
}
