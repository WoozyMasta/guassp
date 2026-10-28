// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package discovery

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/woozymasta/guassp/internal/sonar"
)

// refresh coalesces concurrent requests and atomically publishes full results.
func (index *BindingIndex) refresh(
	ctx context.Context,
	observed *Snapshot,
	force bool,
) (*Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	index.mu.Lock()
	if !force && index.snapshot != observed {
		snapshot := index.snapshot
		if snapshot != nil {
			index.mu.Unlock()
			return snapshot, nil
		}
	}

	if flight := index.flight; flight != nil {
		flight.waiters++
		index.mu.Unlock()
		select {
		case <-flight.done:
			return flight.snapshot, flight.err

		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if !force && observed != nil && !index.lastMissRefresh.IsZero() &&
		index.now().Sub(index.lastMissRefresh) < missRefreshCooldown {
		snapshot := index.snapshot
		index.mu.Unlock()

		return snapshot, nil
	}
	if !force && observed != nil {
		index.lastMissRefresh = index.now()
	}

	flight := &refreshFlight{done: make(chan struct{})}
	previous := index.snapshot
	index.flight = flight

	index.mu.Unlock()
	snapshot, err := index.buildSnapshot(ctx, previous)
	index.mu.Lock()

	if err == nil {
		index.snapshot = snapshot
		index.lastMissRefresh = snapshot.refreshedAt
	}

	flight.snapshot = index.snapshot
	flight.err = err
	index.flight = nil
	close(flight.done)
	index.mu.Unlock()

	if err != nil {
		return flight.snapshot, err
	}

	return snapshot, nil
}

// buildSnapshot reads all projects and bindings before constructing the index.
func (index *BindingIndex) buildSnapshot(ctx context.Context, previous *Snapshot) (*Snapshot, error) {
	projects, err := index.source.Projects(ctx)
	if err != nil {
		return nil, fmt.Errorf("list SonarQube projects for discovery: %w", err)
	}

	snapshot := &Snapshot{
		byGitLabProject:   make(map[int64][]BindingRecord),
		bySonarProjectKey: make(map[string]BindingRecord),
	}

	seen := make(map[string]struct{}, len(projects))
	almKeys := make(map[string]struct{})
	bindings := make(map[string]BindingRecord)
	staleBindings := make(map[string]BindingRecord)
	for _, project := range projects {
		if project.Key == "" {
			continue
		}

		if _, exists := seen[project.Key]; exists {
			continue
		}

		seen[project.Key] = struct{}{}

		binding, err := index.source.Binding(ctx, project.Key)
		if errors.Is(err, sonar.ErrNotBound) {
			continue
		}

		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, fmt.Errorf("get ALM binding for SonarQube project %q: %w", project.Key, err)
			}

			if errors.Is(err, sonar.ErrInvalidRepositoryID) {
				if binding.ALM != "gitlab" || !index.usesALMKey(binding.Key) {
					continue
				}
				if index.almKey == "" && binding.Key != "" {
					almKeys[binding.Key] = struct{}{}
				}

				snapshot.warnings = append(snapshot.warnings, Warning{
					ProjectKey: project.Key,
					Reason:     "GitLab binding has an invalid repository ID",
				})

				continue
			}

			snapshot.warnings = append(snapshot.warnings, Warning{
				ProjectKey: project.Key,
				Reason:     "GitLab binding lookup failed",
			})
			if record, exists := previous.Binding(project.Key); exists && index.usesALMKey(record.ALMKey) {
				record.Project.BindingStale = true
				staleBindings[project.Key] = record
				if index.almKey == "" {
					almKeys[record.ALMKey] = struct{}{}
				}
			}

			continue
		}

		if binding.ALM != "gitlab" || !index.usesALMKey(binding.Key) {
			continue
		}
		if binding.Key == "" {
			snapshot.warnings = append(snapshot.warnings, Warning{
				ProjectKey: project.Key,
				Reason:     "GitLab binding has no ALM setting key",
			})

			continue
		}
		if index.almKey == "" {
			almKeys[binding.Key] = struct{}{}
		}

		projectID, parseErr := strconv.ParseInt(binding.Repository, 10, 64)
		if parseErr != nil || projectID < 1 || (binding.ProjectID > 0 && binding.ProjectID != projectID) {
			snapshot.warnings = append(snapshot.warnings, Warning{
				ProjectKey: project.Key,
				Reason:     "GitLab binding has an invalid repository ID",
			})

			continue
		}

		bindings[project.Key] = BindingRecord{
			Project:         projectFromSonar(project),
			GitLabProjectID: projectID,
			ALMKey:          binding.Key,
		}
	}

	if index.almKey == "" {
		if len(almKeys) > 1 {
			return nil, errors.New("multiple GitLab ALM settings found; configure sonarqube.alm_key")
		}
		for key := range almKeys {
			snapshot.selectedALMKey = key
		}
	} else {
		snapshot.selectedALMKey = index.almKey
	}

	for key, record := range staleBindings {
		if _, hasFreshBinding := bindings[key]; !hasFreshBinding && record.ALMKey == snapshot.selectedALMKey {
			bindings[key] = record
		}
	}

	for _, record := range bindings {
		snapshot.byGitLabProject[record.GitLabProjectID] = append(
			snapshot.byGitLabProject[record.GitLabProjectID], record,
		)
		snapshot.bySonarProjectKey[record.Project.Key] = record
	}
	for projectID, records := range snapshot.byGitLabProject {
		slices.SortFunc(records, func(left, right BindingRecord) int {
			return cmp.Compare(left.Project.Key, right.Project.Key)
		})
		snapshot.byGitLabProject[projectID] = records
	}

	snapshot.refreshedAt = index.now()

	return snapshot, nil
}

// usesALMKey reports whether a binding belongs to the configured ALM setting.
func (index *BindingIndex) usesALMKey(key string) bool {
	return index.almKey == "" || key == index.almKey
}

// projectFromSonar copies the discovery fields from the API model.
func projectFromSonar(project sonar.Project) Project {
	return Project{
		Key:        project.Key,
		Name:       project.Name,
		Visibility: project.Visibility,
	}
}
