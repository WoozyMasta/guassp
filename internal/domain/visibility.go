// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package domain

import "errors"

// GitLabVisibility is a supported source visibility value.
type GitLabVisibility string

// SonarVisibility is a supported target visibility value.
type SonarVisibility string

// VisibilityMode selects whether the configured mapping is applied.
type VisibilityMode string

const (
	// VisibilityMap maps GitLab visibility to SonarQube visibility.
	VisibilityMap VisibilityMode = "map"
	// VisibilityIgnore leaves SonarQube visibility unchanged.
	VisibilityIgnore VisibilityMode = "ignore"
)

// VisibilityPolicy applies the configured GitLab-to-Sonar visibility behavior.
type VisibilityPolicy struct {
	// Mapping maps GitLab visibility values to SonarQube values.
	Mapping map[GitLabVisibility]SonarVisibility
	// Mode selects mapping or leaves SonarQube visibility unchanged.
	Mode VisibilityMode
}

// Resolve returns the target visibility, whether it should be applied, or an error.
func (policy VisibilityPolicy) Resolve(source GitLabVisibility) (SonarVisibility, bool, error) {
	switch policy.Mode {
	case VisibilityIgnore:
		return "", false, nil

	case VisibilityMap:
		if source != "public" && source != "internal" && source != "private" {
			return "", false, errors.New("unsupported GitLab visibility")
		}

		visibility, exists := policy.Mapping[source]
		if !exists {
			return "", false, errors.New("GitLab visibility has no SonarQube mapping")
		}

		if visibility != "public" && visibility != "private" {
			return "", false, errors.New("unsupported SonarQube visibility")
		}

		return visibility, true, nil

	default:
		return "", false, errors.New("unsupported visibility mode")
	}
}

// DefaultVisibilityMap returns the standard GitLab-to-Sonar visibility policy.
func DefaultVisibilityMap() map[GitLabVisibility]SonarVisibility {
	return map[GitLabVisibility]SonarVisibility{
		"public":   "public",
		"internal": "private",
		"private":  "private",
	}
}
