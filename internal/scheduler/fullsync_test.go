// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package scheduler

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/woozymasta/guassp/internal/config"
	"github.com/woozymasta/guassp/internal/discovery"
	"github.com/woozymasta/guassp/internal/sonar"
)

type fullSyncSource struct {
	projects []sonar.Project
	bindings map[string]sonar.Binding
	err      error
	calls    atomic.Int32
}

type fullSyncStatusObserver chan FullSyncStatus

// ObserveFullSyncStatus reports one completed test cycle.
func (observer fullSyncStatusObserver) ObserveFullSyncStatus(status FullSyncStatus) {
	observer <- status
}

// Projects returns the fixture project list or its configured error.
func (source *fullSyncSource) Projects(_ context.Context) ([]sonar.Project, error) {
	source.calls.Add(1)
	return source.projects, source.err
}

// Binding returns a fixture ALM binding for a SonarQube project.
func (source *fullSyncSource) Binding(_ context.Context, projectKey string) (sonar.Binding, error) {
	binding, exists := source.bindings[projectKey]
	if !exists {
		return sonar.Binding{}, sonar.ErrNotBound
	}

	return binding, nil
}

type fullSyncSubmitter struct {
	mu          sync.Mutex
	submissions []fullSyncSubmission
	errors      map[int64]error
	reject      bool
	err         error
}

type fullSyncSubmission struct {
	projectID int64
	priority  Priority
	source    string
}

// Submit records a project submission and returns its configured outcome.
func (submitter *fullSyncSubmitter) Submit(
	projectID int64,
	priority Priority,
	source string,
) (Submission, error) {
	submitter.mu.Lock()
	defer submitter.mu.Unlock()
	submitter.submissions = append(submitter.submissions, fullSyncSubmission{
		projectID: projectID,
		priority:  priority,
		source:    source,
	})
	if err := submitter.errors[projectID]; err != nil {
		return Submission{}, err
	}
	if submitter.err != nil {
		return Submission{}, submitter.err
	}

	return Submission{Accepted: !submitter.reject}, nil
}

func TestFullSyncWaitsForScheduleAndSubmitsUniqueProjectsOnManualTrigger(t *testing.T) {
	statuses := make(fullSyncStatusObserver, 1)
	source := &fullSyncSource{
		projects: []sonar.Project{{Key: "one"}, {Key: "two"}, {Key: "three"}},
		bindings: map[string]sonar.Binding{
			"one":   {Key: "GitLab", ALM: "gitlab", Repository: "42", ProjectID: 42},
			"two":   {Key: "GitLab", ALM: "gitlab", Repository: "42", ProjectID: 42},
			"three": {Key: "GitLab", ALM: "gitlab", Repository: "99", ProjectID: 99},
		},
	}
	index := newFullSyncTestIndex(t, source)
	queue := &fullSyncSubmitter{}
	timers := make(chan *fakeDailyTimer, 1)
	fullSync, err := newFullSync(
		"03:00",
		index,
		queue,
		zerolog.Nop(),
		time.Now,
		func(delay time.Duration) dailyTimer {
			timer := &fakeDailyTimer{channel: make(chan time.Time), delay: delay}
			timers <- timer
			return timer
		},
	)
	if err != nil {
		t.Fatalf("newFullSync: %v", err)
	}

	fullSync.SetObserver(statuses)
	if err := fullSync.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	timer := awaitSignal(t, timers, "daily timer")
	if source.calls.Load() != 0 {
		t.Fatalf("startup refresh calls = %d, want 0", source.calls.Load())
	}
	if status := fullSync.Status(); !status.StartedAt.IsZero() {
		t.Fatalf("startup status shows a full-sync cycle: %+v", status)
	}
	if !fullSync.Trigger() || fullSync.Trigger() {
		t.Fatal("manual trigger was not accepted exactly once")
	}
	status := awaitSignal(t, statuses, "manual full-sync status")

	if status.Running || status.Failed || status.ProjectsFound != 2 || status.Submitted != 2 ||
		status.ErrorCount != 0 || status.StartedAt.IsZero() || status.FinishedAt.IsZero() {
		t.Fatalf("status = %+v", status)
	}
	if len(queue.submissions) != 2 || queue.submissions[0] != (fullSyncSubmission{
		projectID: 42, priority: PriorityLow, source: "manual_full_sync",
	}) || queue.submissions[1] != (fullSyncSubmission{
		projectID: 99, priority: PriorityLow, source: "manual_full_sync",
	}) {
		t.Fatalf("submissions = %+v", queue.submissions)
	}
	fullSync.Stop()
	if !timer.stopped.Load() {
		t.Fatal("Stop did not stop the active timer")
	}
}

func TestScheduledFullSyncDiscoveryFailureIsObservable(t *testing.T) {
	source := &fullSyncSource{err: errors.New("upstream secret")}
	index := newFullSyncTestIndex(t, source)
	timers := make(chan *fakeDailyTimer, 1)
	fullSync, err := newFullSync(
		"03:00",
		index,
		&fullSyncSubmitter{},
		zerolog.Nop(),
		time.Now,
		func(delay time.Duration) dailyTimer {
			timer := &fakeDailyTimer{channel: make(chan time.Time), delay: delay}
			timers <- timer
			return timer
		},
	)
	if err != nil {
		t.Fatalf("newFullSync: %v", err)
	}
	if err := fullSync.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	timer := awaitSignal(t, timers, "initial daily timer")
	if source.calls.Load() != 0 {
		t.Fatalf("startup refresh calls = %d, want 0", source.calls.Load())
	}
	timer.channel <- time.Now()
	awaitSignal(t, timers, "daily timer after scheduled failure")

	status := fullSync.Status()
	if !status.Failed || status.ErrorCount != 1 || status.Running || status.FinishedAt.IsZero() {
		t.Fatalf("status = %+v", status)
	}
	if source.calls.Load() != 1 {
		t.Fatalf("project refresh calls = %d, want 1", source.calls.Load())
	}
	fullSync.Stop()
	if !timer.stopped.Load() {
		t.Fatal("Stop did not stop the initial timer")
	}
}

func TestFullSyncContinuesAfterProjectSubmissionFailure(t *testing.T) {
	index := newFullSyncTestIndex(t, &fullSyncSource{
		projects: []sonar.Project{{Key: "one"}, {Key: "two"}},
		bindings: map[string]sonar.Binding{
			"one": {Key: "GitLab", ALM: "gitlab", Repository: "42", ProjectID: 42},
			"two": {Key: "GitLab", ALM: "gitlab", Repository: "99", ProjectID: 99},
		},
	})
	queue := &fullSyncSubmitter{errors: map[int64]error{42: errors.New("scheduler unavailable")}}
	fullSync, err := NewFullSync("", index, queue, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewFullSync: %v", err)
	}
	if !fullSync.runCycle(context.Background(), "test") {
		t.Fatal("full-sync cycle did not run")
	}

	status := fullSync.Status()
	if !status.Failed || status.ErrorCount != 1 || status.Submitted != 1 || status.ProjectsFound != 2 {
		t.Fatalf("status = %+v", status)
	}
	if len(queue.submissions) != 2 || queue.submissions[0].projectID != 42 ||
		queue.submissions[1].projectID != 99 || queue.submissions[1].priority != PriorityLow {
		t.Fatalf("submissions = %+v; the second project must still be queued low priority", queue.submissions)
	}
}

func TestDisabledFullSyncDoesNotRunStartupCycle(t *testing.T) {
	source := &fullSyncSource{
		projects: []sonar.Project{{Key: "project"}},
		bindings: map[string]sonar.Binding{
			"project": {Key: "GitLab", ALM: "gitlab", Repository: "42", ProjectID: 42},
		},
	}
	index := newFullSyncTestIndex(t, source)
	queue := &fullSyncSubmitter{}
	fullSync, err := NewFullSync("", index, queue, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewFullSync: %v", err)
	}
	if err := fullSync.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	status := fullSync.Status()
	if source.calls.Load() != 0 || len(queue.submissions) != 0 || !status.StartedAt.IsZero() ||
		!status.FinishedAt.IsZero() || !status.NextAt.IsZero() {
		t.Fatalf("disabled full-sync ran work: calls=%d submissions=%+v status=%+v",
			source.calls.Load(), queue.submissions, status)
	}
	fullSync.Stop()
}

func TestFullSyncSchedulesUsingLocalTimeAndStopsTimer(t *testing.T) {
	location := time.FixedZone("test", 3*60*60)
	nowMu := sync.Mutex{}
	now := time.Date(2026, time.October, 22, 2, 59, 0, 0, location)
	clock := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}

	setNow := func(value time.Time) {
		nowMu.Lock()
		now = value
		nowMu.Unlock()
	}
	refreshes := make(chan struct{}, 3)
	refresher := &fakeBindingRefresher{refresh: func(context.Context) (*discovery.Snapshot, error) {
		refreshes <- struct{}{}
		return &discovery.Snapshot{}, nil
	}}

	timers := make(chan *fakeDailyTimer, 3)
	fullSync, err := newFullSync(
		config.DailyTime("03:00"),
		refresher,
		&fullSyncSubmitter{},
		zerolog.Nop(),
		clock,
		func(delay time.Duration) dailyTimer {
			timer := &fakeDailyTimer{channel: make(chan time.Time, 1), delay: delay}
			timers <- timer
			return timer
		},
	)
	if err != nil {
		t.Fatalf("newFullSync: %v", err)
	}
	if err := fullSync.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	firstTimer := awaitSignal(t, timers, "first timer")
	if firstTimer.delay != time.Minute {
		t.Fatalf("first timer delay = %s, want 1m", firstTimer.delay)
	}

	setNow(time.Date(2026, time.October, 22, 3, 0, 0, 0, location))
	firstTimer.channel <- clock()
	awaitSignal(t, refreshes, "scheduled refresh")
	secondTimer := awaitSignal(t, timers, "recalculated timer")
	if secondTimer.delay != 24*time.Hour {
		t.Fatalf("recalculated timer delay = %s, want 24h", secondTimer.delay)
	}

	fullSync.Stop()
	if !secondTimer.stopped.Load() {
		t.Fatal("Stop did not stop the active timer")
	}
}

func TestFullSyncCoalescesOverlappingDiscoveryCycles(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	refresher := &fakeBindingRefresher{refresh: func(ctx context.Context) (*discovery.Snapshot, error) {
		started <- struct{}{}
		select {
		case <-release:
			return &discovery.Snapshot{}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	fullSync, err := NewFullSync("", refresher, &fullSyncSubmitter{}, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewFullSync: %v", err)
	}

	cycleDone := make(chan bool, 1)
	go func() { cycleDone <- fullSync.runCycle(context.Background(), "test") }()
	awaitSignal(t, started, "first discovery cycle")
	if fullSync.runCycle(context.Background(), "test") {
		t.Fatal("overlapping discovery cycle was started")
	}
	close(release)
	if !awaitSignal(t, cycleDone, "first cycle completion") {
		t.Fatal("first discovery cycle did not run")
	}
}

func TestManualFullSyncCoalescesQueuedAndRunningTriggers(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	statuses := make(fullSyncStatusObserver, 1)
	refresher := &fakeBindingRefresher{refresh: func(ctx context.Context) (*discovery.Snapshot, error) {
		started <- struct{}{}
		select {
		case <-release:
			return &discovery.Snapshot{}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}

	fullSync, err := NewFullSync("", refresher, &fullSyncSubmitter{}, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewFullSync: %v", err)
	}

	fullSync.SetObserver(statuses)
	if err := fullSync.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !fullSync.Trigger() || !fullSync.Status().Queued {
		t.Fatal("manual full-sync trigger was not queued")
	}

	for range 10 {
		if fullSync.Trigger() {
			t.Fatal("duplicate manual full-sync trigger was accepted")
		}
	}
	awaitSignal(t, started, "manual full-sync start")
	if fullSync.Status().Queued || !fullSync.Status().Running || fullSync.Trigger() {
		t.Fatal("manual trigger was not coalesced while the cycle was running")
	}

	close(release)
	awaitSignal(t, statuses, "manual full-sync completion")
	if !fullSync.Trigger() {
		t.Fatal("manual full-sync trigger was not accepted after completion")
	}
	fullSync.Stop()
}

func TestNextFullSyncRollsToNextLocalDay(t *testing.T) {
	location := time.FixedZone("test", -5*60*60)
	now := time.Date(2026, time.October, 22, 3, 0, 0, 0, location)
	want := time.Date(2026, time.October, 23, 3, 0, 0, 0, location)
	if got := nextFullSync("03:00", now); !got.Equal(want) {
		t.Fatalf("nextFullSync = %s, want %s", got, want)
	}
	if got := nextFullSync("", now); !got.IsZero() {
		t.Fatalf("disabled nextFullSync = %s, want zero", got)
	}
}

func TestNewFullSyncRejectsInvalidDailyTime(t *testing.T) {
	if _, err := NewFullSync("25:00", &fakeBindingRefresher{}, &fullSyncSubmitter{}, zerolog.Nop()); err == nil {
		t.Fatal("NewFullSync accepted an invalid daily time")
	}
}

type fakeBindingRefresher struct {
	refresh func(context.Context) (*discovery.Snapshot, error)
}

// Refresh invokes the configured test discovery behavior.
func (refresher *fakeBindingRefresher) Refresh(ctx context.Context) (*discovery.Snapshot, error) {
	return refresher.refresh(ctx)
}

type fakeDailyTimer struct {
	channel chan time.Time
	delay   time.Duration
	stopped atomic.Bool
}

// C returns the test timer channel.
func (timer *fakeDailyTimer) C() <-chan time.Time {
	return timer.channel
}

// Stop records that the test timer was stopped.
func (timer *fakeDailyTimer) Stop() bool {
	return !timer.stopped.Swap(true)
}

// newFullSyncTestIndex creates an index backed by one test source.
func newFullSyncTestIndex(t *testing.T, source *fullSyncSource) *discovery.BindingIndex {
	t.Helper()
	index, err := discovery.NewBindingIndex(source, "")
	if err != nil {
		t.Fatalf("NewBindingIndex: %v", err)
	}

	return index
}

// awaitSignal waits for one channel event and fails with a bounded timeout.
func awaitSignal[T any](t *testing.T, channel <-chan T, name string) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(3 * time.Second):
		var zero T
		t.Fatalf("timed out waiting for %s", name)
		return zero
	}
}
