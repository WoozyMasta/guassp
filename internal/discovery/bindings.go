// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

// Package discovery indexes SonarQube projects by their GitLab bindings.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/woozymasta/guassp/internal/sonar"
)

// NewBindingIndex creates a binding index with an optional ALM setting filter.
func NewBindingIndex(source SonarSource, almKey string) (*BindingIndex, error) {
	if source == nil {
		return nil, errors.New("SonarQube discovery source is required")
	}

	return &BindingIndex{source: source, almKey: almKey, now: time.Now}, nil
}

// Snapshot returns the current complete snapshot, loading it when absent.
func (index *BindingIndex) Snapshot(ctx context.Context) (*Snapshot, error) {
	index.mu.Lock()
	snapshot := index.snapshot
	index.mu.Unlock()
	if snapshot != nil {
		return snapshot, nil
	}

	return index.refresh(ctx, nil, false)
}

// Refresh builds and publishes a complete binding snapshot.
func (index *BindingIndex) Refresh(ctx context.Context) (*Snapshot, error) {
	return index.refresh(ctx, nil, true)
}

// Lookup returns SonarQube targets and limits full refreshes after project misses.
func (index *BindingIndex) Lookup(ctx context.Context, gitLabProjectID int64) ([]Project, error) {
	snapshot, err := index.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if projects := snapshot.Projects(gitLabProjectID); len(projects) != 0 {
		return projects, nil
	}

	snapshot, err = index.refresh(ctx, snapshot, false)
	if err != nil {
		return nil, err
	}

	return snapshot.Projects(gitLabProjectID), nil
}

// VerifyBinding confirms that a target still belongs to the requested GitLab project.
//
//nolint:nilerr // Invalid or missing bindings are expected mismatches.
func (index *BindingIndex) VerifyBinding(
	ctx context.Context,
	gitLabProjectID int64,
	sonarProjectKey string,
) (bool, error) {
	index.mu.Lock()
	snapshot := index.snapshot
	index.mu.Unlock()
	record, exists := snapshot.Binding(sonarProjectKey)
	if !exists || record.GitLabProjectID != gitLabProjectID {
		return false, nil
	}

	binding, err := index.source.Binding(ctx, sonarProjectKey)
	if errors.Is(err, sonar.ErrNotBound) || errors.Is(err, sonar.ErrInvalidRepositoryID) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("re-verify SonarQube project binding: %w", err)
	}
	if binding.ALM != "gitlab" || binding.Key != snapshot.selectedALMKey || binding.Key != record.ALMKey {
		return false, nil
	}

	projectID, parseErr := strconv.ParseInt(binding.Repository, 10, 64)
	if parseErr != nil || projectID < 1 || (binding.ProjectID > 0 && binding.ProjectID != projectID) {
		return false, nil
	}

	return projectID == gitLabProjectID, nil
}
