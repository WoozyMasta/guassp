// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package discovery

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/woozymasta/guassp/internal/sonar"
)

type fakeSonarSource struct {
	mu           sync.Mutex
	projects     []sonar.Project
	projectsErr  error
	bindings     map[string]sonar.Binding
	bindingErrs  map[string]error
	searchResult []sonar.Project
	searchErr    error
	projectLoads int
	projectLoad  func(int) []sonar.Project
	entered      chan struct{}
	release      chan struct{}
}

func (source *fakeSonarSource) Projects(ctx context.Context) ([]sonar.Project, error) {
	source.mu.Lock()
	source.projectLoads++
	loadNumber := source.projectLoads
	projects := append([]sonar.Project(nil), source.projects...)
	projectLoad := source.projectLoad
	entered := source.entered
	release := source.release
	source.mu.Unlock()
	if source.projectsErr != nil {
		return nil, source.projectsErr
	}

	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}

	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if projectLoad != nil {
		projects = projectLoad(loadNumber)
	}

	return projects, nil
}

func (source *fakeSonarSource) Binding(_ context.Context, projectKey string) (sonar.Binding, error) {
	source.mu.Lock()
	defer source.mu.Unlock()

	if err := source.bindingErrs[projectKey]; err != nil {
		return source.bindings[projectKey], err
	}

	binding, exists := source.bindings[projectKey]
	if !exists {
		return sonar.Binding{}, sonar.ErrNotBound
	}

	return binding, nil
}

func (source *fakeSonarSource) SearchProjects(
	_ context.Context,
	query string,
) ([]sonar.Project, error) {
	if source.searchErr != nil {
		return nil, source.searchErr
	}
	if query == "" {
		return nil, errors.New("empty query")
	}

	return append([]sonar.Project(nil), source.searchResult...), nil
}

func (source *fakeSonarSource) projectLoadCount() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.projectLoads
}

func TestBindingIndexFiltersAndGroupsBindings(t *testing.T) {
	source := &fakeSonarSource{
		projects: []sonar.Project{
			{Key: "one", Name: "One"},
			{Key: "two", Name: "Two"},
			{Key: "other", Name: "Other"},
			{Key: "different-setting", Name: "Different"},
			{Key: "malformed", Name: "Malformed"},
			{Key: "malformed-other-setting", Name: "Malformed other setting"},
			{Key: "unbound", Name: "Unbound"},
		},
		bindings: map[string]sonar.Binding{
			"one":               {Key: "GitLab", ALM: "gitlab", Repository: "42", ProjectID: 42},
			"two":               {Key: "GitLab", ALM: "gitlab", Repository: "42", ProjectID: 42},
			"other":             {Key: "GitHub", ALM: "github", Repository: "99"},
			"different-setting": {Key: "Other", ALM: "gitlab", Repository: "99", ProjectID: 99},
			"malformed":         {Key: "GitLab", ALM: "gitlab", Repository: "../42"},
			"malformed-other-setting": {
				Key: "Other", ALM: "gitlab", Repository: "../99",
			},
		},
		bindingErrs: map[string]error{
			"malformed-other-setting": fmt.Errorf("binding response: %w", sonar.ErrInvalidRepositoryID),
		},
	}
	index := testBindingIndex(t, source, "GitLab")

	snapshot, err := index.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	projects := snapshot.Projects(42)
	if len(projects) != 2 || projects[0].Key != "one" || projects[1].Key != "two" {
		t.Fatalf("projects for GitLab project 42 = %+v", projects)
	}
	if got := snapshot.GitLabProjectIDs(); !reflect.DeepEqual(got, []int64{42}) {
		t.Fatalf("GitLab project IDs = %v, want [42]", got)
	}
	warnings := snapshot.Warnings()
	if len(warnings) != 1 || warnings[0].ProjectKey != "malformed" {
		t.Fatalf("warnings = %+v, want malformed binding warning", warnings)
	}
}

func TestBindingIndexSkipsInvalidRepositoryError(t *testing.T) {
	source := &fakeSonarSource{
		projects: []sonar.Project{{Key: "malformed"}},
		bindings: map[string]sonar.Binding{
			"malformed": {Key: "GitLab", ALM: "gitlab", Repository: "../42"},
		},
		bindingErrs: map[string]error{
			"malformed": fmt.Errorf("binding response: %w", sonar.ErrInvalidRepositoryID),
		},
	}
	index := testBindingIndex(t, source, "")

	snapshot, err := index.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if len(snapshot.Warnings()) != 1 || len(snapshot.GitLabProjectIDs()) != 0 {
		t.Fatalf("snapshot warnings=%+v IDs=%v", snapshot.Warnings(), snapshot.GitLabProjectIDs())
	}
}

func TestBindingIndexLookupRefreshesOnMiss(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	source := &fakeSonarSource{
		projectLoad: func(call int) []sonar.Project {
			if call == 1 {
				return nil
			}
			return []sonar.Project{{Key: "project", Name: "Project"}}
		},
		bindings: map[string]sonar.Binding{
			"project": {Key: "GitLab", ALM: "gitlab", Repository: "42", ProjectID: 42},
		},
	}
	index := testBindingIndex(t, source, "")
	index.now = func() time.Time { return now }

	projects, err := index.Lookup(context.Background(), 42)
	if err != nil || len(projects) != 0 {
		t.Fatalf("initial Lookup = %+v, %v; want no targets", projects, err)
	}
	if got := source.projectLoadCount(); got != 1 {
		t.Fatalf("project loads = %d, want one initial load", got)
	}
	for projectID := int64(1); projectID < 100; projectID++ {
		if _, err := index.Lookup(context.Background(), projectID); err != nil {
			t.Fatalf("Lookup(%d) during cooldown: %v", projectID, err)
		}
	}
	if got := source.projectLoadCount(); got != 1 {
		t.Fatalf("arbitrary misses triggered %d project scans, want one", got)
	}

	now = now.Add(missRefreshCooldown)
	projects, err = index.Lookup(context.Background(), 42)
	if err != nil || len(projects) != 1 || projects[0].Key != "project" {
		t.Fatalf("Lookup after cooldown = %+v, %v", projects, err)
	}
	if got := source.projectLoadCount(); got != 2 {
		t.Fatalf("project loads = %d, want one refresh after cooldown", got)
	}
}

func TestBindingIndexKeepsPreviousSnapshotOnRefreshFailure(t *testing.T) {
	source := &fakeSonarSource{
		projects: []sonar.Project{{Key: "initial"}},
		bindings: map[string]sonar.Binding{
			"initial": {Key: "GitLab", ALM: "gitlab", Repository: "7", ProjectID: 7},
		},
	}
	index := testBindingIndex(t, source, "")
	initial, err := index.Refresh(context.Background())
	if err != nil {
		t.Fatalf("initial Refresh: %v", err)
	}

	source.mu.Lock()
	source.projects = []sonar.Project{{Key: "broken"}}
	source.bindingErrs = map[string]error{"broken": errors.New("upstream unavailable")}
	source.mu.Unlock()
	source.projectsErr = errors.New("project search unavailable")
	if _, err := index.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh succeeded with a project search error")
	}

	snapshot, err := index.Snapshot(context.Background())
	if err != nil || snapshot != initial || len(snapshot.Projects(7)) != 1 {
		t.Fatalf("Snapshot after failed refresh = %p, %v; want prior complete snapshot", snapshot, err)
	}
}

func TestBindingIndexKeepsUsableBindingsWhenOneBindingReadFails(t *testing.T) {
	source := &fakeSonarSource{
		projects: []sonar.Project{{Key: "working"}, {Key: "broken"}},
		bindings: map[string]sonar.Binding{
			"working": {Key: "GitLab", ALM: "gitlab", Repository: "42", ProjectID: 42},
			"broken":  {Key: "GitLab", ALM: "gitlab", Repository: "43", ProjectID: 43},
		},
	}
	index := testBindingIndex(t, source, "GitLab")
	initial, err := index.Refresh(context.Background())
	if err != nil {
		t.Fatalf("initial Refresh: %v", err)
	}

	source.mu.Lock()
	source.bindingErrs = map[string]error{"broken": errors.New("binding API unavailable")}
	source.mu.Unlock()
	snapshot, err := index.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh with one binding failure: %v", err)
	}
	if snapshot == initial || len(snapshot.Projects(42)) != 1 || len(snapshot.Projects(43)) != 1 {
		t.Fatalf("usable targets were lost: projects 42=%+v, 43=%+v", snapshot.Projects(42), snapshot.Projects(43))
	}
	if record, exists := snapshot.Binding("broken"); !exists || !record.Project.BindingStale {
		t.Fatalf("broken binding record = %+v, %t; want stale hint", record, exists)
	}
	if len(snapshot.Warnings()) != 1 {
		t.Fatalf("warnings = %+v, want one binding warning", snapshot.Warnings())
	}

	verified, err := index.VerifyBinding(context.Background(), 42, "working")
	if err != nil || !verified {
		t.Fatalf("VerifyBinding(working) = %t, %v", verified, err)
	}
	if _, err := index.VerifyBinding(context.Background(), 43, "broken"); err == nil {
		t.Fatal("VerifyBinding hid the live binding error")
	}
}

func TestBindingIndexDoesNotPublishSnapshotAfterBindingReadCancellation(t *testing.T) {
	source := &fakeSonarSource{
		projects: []sonar.Project{{Key: "project"}},
		bindingErrs: map[string]error{
			"project": context.Canceled,
		},
	}
	index := testBindingIndex(t, source, "GitLab")
	if _, err := index.Refresh(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Refresh error = %v; want context cancellation", err)
	}
	index.mu.Lock()
	snapshot := index.snapshot
	index.mu.Unlock()
	if snapshot != nil {
		t.Fatalf("canceled refresh published a snapshot: %+v", snapshot)
	}
}

func TestBindingIndexRejectsAmbiguousGitLabALMKeys(t *testing.T) {
	source := &fakeSonarSource{
		projects: []sonar.Project{{Key: "one"}, {Key: "two"}},
		bindings: map[string]sonar.Binding{
			"one": {Key: "GitLab one", ALM: "gitlab", Repository: "1", ProjectID: 1},
			"two": {Key: "GitLab two", ALM: "gitlab", Repository: "2", ProjectID: 2},
		},
	}
	index := testBindingIndex(t, source, "")
	if _, err := index.Refresh(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "configure sonarqube.alm_key") {
		t.Fatalf("Refresh error = %v; want explicit ALM key ambiguity", err)
	}

	index.mu.Lock()
	snapshot := index.snapshot
	index.mu.Unlock()
	if snapshot != nil {
		t.Fatalf("ambiguous refresh published a snapshot: %+v", snapshot)
	}
}

func TestBindingIndexRejectsReboundTargetDuringLiveVerification(t *testing.T) {
	source := &fakeSonarSource{
		projects: []sonar.Project{{Key: "project"}},
		bindings: map[string]sonar.Binding{
			"project": {Key: "GitLab", ALM: "gitlab", Repository: "42", ProjectID: 42},
		},
	}
	index := testBindingIndex(t, source, "GitLab")
	if _, err := index.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	source.mu.Lock()
	source.bindings["project"] = sonar.Binding{
		Key: "GitLab", ALM: "gitlab", Repository: "99", ProjectID: 99,
	}
	source.mu.Unlock()
	verified, err := index.VerifyBinding(context.Background(), 42, "project")
	if err != nil || verified {
		t.Fatalf("VerifyBinding(rebound project) = %t, %v; want false, nil", verified, err)
	}
}

func TestBindingIndexConcurrentRefreshAndSnapshot(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	source := &fakeSonarSource{
		projects: []sonar.Project{{Key: "old"}},
		bindings: map[string]sonar.Binding{
			"old":   {Key: "GitLab", ALM: "gitlab", Repository: "1", ProjectID: 1},
			"new-a": {Key: "GitLab", ALM: "gitlab", Repository: "2", ProjectID: 2},
			"new-b": {Key: "GitLab", ALM: "gitlab", Repository: "3", ProjectID: 3},
		},
		projectLoad: func(call int) []sonar.Project {
			if call == 1 {
				return []sonar.Project{{Key: "old"}}
			}
			return []sonar.Project{{Key: "new-a"}, {Key: "new-b"}}
		},
	}
	index := testBindingIndex(t, source, "")
	index.now = func() time.Time { return now }
	old, err := index.Refresh(context.Background())
	if err != nil {
		t.Fatalf("initial Refresh: %v", err)
	}

	source.mu.Lock()
	source.entered = make(chan struct{}, 1)
	source.release = make(chan struct{})
	source.mu.Unlock()

	const refreshers = 8
	start := make(chan struct{})
	results := make(chan *Snapshot, refreshers)
	errs := make(chan error, refreshers)

	var wait sync.WaitGroup
	wait.Add(refreshers)

	for range refreshers {
		go func() {
			defer wait.Done()
			<-start
			snapshot, err := index.Refresh(context.Background())
			results <- snapshot
			errs <- err
		}()
	}

	close(start)
	<-source.entered
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		index.mu.Lock()
		waiters := index.flight.waiters
		index.mu.Unlock()
		if waiters == refreshers-1 {
			break
		}
		select {
		case <-deadline.C:
			t.Fatalf("refresh waiters = %d, want %d", waiters, refreshers-1)
		default:
			runtime.Gosched()
		}
	}

	reader, err := index.Snapshot(context.Background())
	if err != nil || reader != old || len(reader.GitLabProjectIDs()) != 1 {
		t.Fatalf("snapshot during refresh = %p, %v; want old complete snapshot", reader, err)
	}

	close(source.release)
	wait.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Refresh: %v", err)
		}
	}
	for snapshot := range results {
		ids := snapshot.GitLabProjectIDs()
		if !reflect.DeepEqual(ids, []int64{1}) && !reflect.DeepEqual(ids, []int64{2, 3}) {
			t.Fatalf("reader observed partial snapshot: IDs=%v", ids)
		}
	}
	if got := source.projectLoadCount(); got != 2 {
		t.Fatalf("project loads = %d, want initial plus one coalesced refresh", got)
	}
}

func TestBindingIndexCoalescesConcurrentMissRefreshes(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	source := &fakeSonarSource{
		projectLoad: func(call int) []sonar.Project {
			if call == 1 {
				return nil
			}

			return []sonar.Project{{Key: "project"}}
		},
		bindings: map[string]sonar.Binding{
			"project": {Key: "GitLab", ALM: "gitlab", Repository: "42", ProjectID: 42},
		},
	}
	index := testBindingIndex(t, source, "GitLab")
	index.now = func() time.Time { return now }
	if _, err := index.Snapshot(context.Background()); err != nil {
		t.Fatalf("initial Snapshot: %v", err)
	}

	now = now.Add(missRefreshCooldown)
	source.mu.Lock()
	source.entered = make(chan struct{}, 1)
	source.release = make(chan struct{})
	source.mu.Unlock()

	const callers = 8
	start := make(chan struct{})
	results := make(chan []Project, callers)
	errors := make(chan error, callers)

	var wait sync.WaitGroup
	wait.Add(callers)

	for range callers {
		go func() {
			defer wait.Done()
			<-start
			projects, err := index.Lookup(context.Background(), 42)
			results <- projects
			errors <- err
		}()
	}
	close(start)
	<-source.entered

	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		index.mu.Lock()
		waiters := index.flight.waiters
		index.mu.Unlock()
		if waiters == callers-1 {
			break
		}
		select {
		case <-deadline.C:
			t.Fatalf("refresh waiters = %d, want %d", waiters, callers-1)
		default:
			runtime.Gosched()
		}
	}

	close(source.release)
	wait.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent Lookup: %v", err)
		}
	}
	for projects := range results {
		if len(projects) != 1 || projects[0].Key != "project" {
			t.Fatalf("concurrent Lookup targets = %+v", projects)
		}
	}
	if got := source.projectLoadCount(); got != 2 {
		t.Fatalf("project loads = %d, want initial plus one coalesced miss refresh", got)
	}
}

func TestLegacyPathFallbackRequiresOneResult(t *testing.T) {
	tests := []struct {
		name     string
		projects []sonar.Project
		found    bool
		bound    bool
	}{
		{name: "none"},
		{name: "one", projects: []sonar.Project{{Key: "project", Name: "group/project"}}, found: true},
		{name: "fuzzy single result", projects: []sonar.Project{{Key: "project", Name: "group/other"}}},
		{
			name: "ambiguous exact results",
			projects: []sonar.Project{
				{Key: "one", Name: "group/project"},
				{Key: "two", Name: "group/project"},
			},
		},
		{
			name:     "already bound result",
			projects: []sonar.Project{{Key: "project", Name: "group/project"}},
			bound:    true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := &fakeSonarSource{searchResult: test.projects}
			if test.bound {
				source.bindings = map[string]sonar.Binding{
					"project": {Key: "GitLab", ALM: "gitlab", Repository: "42", ProjectID: 42},
				}
			}
			index := testBindingIndex(t, source, "")
			project, found, err := index.LegacyPathFallback(context.Background(), "group/project")
			if err != nil || found != test.found {
				t.Fatalf("LegacyPathFallback = %+v, %t, %v", project, found, err)
			}
			if found && project.Key != "project" {
				t.Fatalf("fallback project = %+v", project)
			}
		})
	}
}

func testBindingIndex(t *testing.T, source SonarSource, almKey string) *BindingIndex {
	t.Helper()
	index, err := NewBindingIndex(source, almKey)
	if err != nil {
		t.Fatalf("NewBindingIndex: %v", err)
	}

	return index
}
