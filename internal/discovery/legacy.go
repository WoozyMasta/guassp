// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package discovery

import (
	"context"
	"errors"
	"fmt"

	"github.com/woozymasta/guassp/internal/sonar"
)

// LegacyProjectSearcher searches SonarQube projects for the optional path fallback.
type LegacyProjectSearcher interface {
	SearchProjects(context.Context, string) ([]sonar.Project, error)
}

// LegacyPathFallback returns a unique, exact-name, unbound SonarQube project.
// Callers must enable the compatibility option before using it.
func (index *BindingIndex) LegacyPathFallback(ctx context.Context, pathWithNamespace string) (Project, bool, error) {
	if pathWithNamespace == "" {
		return Project{}, false, errors.New("GitLab project path is required for legacy discovery")
	}

	searcher, ok := index.source.(LegacyProjectSearcher)
	if !ok {
		return Project{}, false, errors.New("SonarQube source does not support legacy project search")
	}

	projects, err := searcher.SearchProjects(ctx, pathWithNamespace)
	if err != nil {
		return Project{}, false, fmt.Errorf("search SonarQube projects by GitLab path: %w", err)
	}

	candidates := make(map[string]sonar.Project)
	for _, project := range projects {
		if project.Key != "" && project.Name == pathWithNamespace {
			candidates[project.Key] = project
		}
	}
	if len(candidates) != 1 {
		return Project{}, false, nil
	}

	var candidate sonar.Project
	for _, project := range candidates {
		candidate = project
	}
	_, err = index.source.Binding(ctx, candidate.Key)
	if errors.Is(err, sonar.ErrNotBound) {
		return projectFromSonar(candidate), true, nil
	}
	if err != nil {
		return Project{}, false, fmt.Errorf("verify legacy SonarQube project binding: %w", err)
	}

	return Project{}, false, nil
}
