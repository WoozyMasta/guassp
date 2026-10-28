// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package discovery

import (
	"context"
	"sync"
	"time"

	"github.com/woozymasta/guassp/internal/sonar"
)

const missRefreshCooldown = time.Minute

// SonarSource provides the project and binding reads needed for discovery.
type SonarSource interface {
	Projects(context.Context) ([]sonar.Project, error)
	Binding(context.Context, string) (sonar.Binding, error)
}

// Project contains the SonarQube project fields used by discovery consumers.
type Project struct {
	// Key is the unique SonarQube project key.
	Key string
	// Name is the SonarQube display name.
	Name string
	// Visibility is the current SonarQube visibility.
	Visibility string
	// BindingStale reports that the target came from a previous binding snapshot.
	BindingStale bool
}

// Warning describes a binding omitted from a successfully built snapshot.
type Warning struct {
	// ProjectKey identifies the SonarQube project with the invalid binding.
	ProjectKey string
	// Reason explains why the binding was skipped without exposing raw input.
	Reason string
}

// BindingRecord links one SonarQube project to its GitLab ALM association.
type BindingRecord struct {
	// ALMKey identifies the SonarQube GitLab ALM configuration.
	ALMKey string
	// Project contains the SonarQube project fields used by discovery consumers.
	Project Project
	// GitLabProjectID is the repository ID in the selected GitLab ALM binding.
	GitLabProjectID int64
}

// Snapshot is an immutable, complete binding index.
type Snapshot struct {
	refreshedAt       time.Time
	byGitLabProject   map[int64][]BindingRecord
	bySonarProjectKey map[string]BindingRecord
	selectedALMKey    string
	warnings          []Warning
}

// BindingIndex owns the current immutable snapshot and serialized refreshes.
type BindingIndex struct {
	source          SonarSource
	snapshot        *Snapshot
	flight          *refreshFlight
	now             func() time.Time
	lastMissRefresh time.Time
	almKey          string
	mu              sync.Mutex
}

// refreshFlight holds one in-progress refresh result for concurrent callers.
type refreshFlight struct {
	done     chan struct{}
	snapshot *Snapshot
	err      error
	waiters  int
}
