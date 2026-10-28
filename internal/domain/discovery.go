// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package domain

// ProjectDiscoveryMode selects how SonarQube targets are found for a GitLab project.
type ProjectDiscoveryMode string

const (
	// ProjectDiscoveryBinding uses explicit SonarQube ALM bindings only.
	ProjectDiscoveryBinding ProjectDiscoveryMode = "binding"
	// ProjectDiscoveryBindingPathFallback enables legacy project-name search on a miss.
	ProjectDiscoveryBindingPathFallback ProjectDiscoveryMode = "binding-path-fallback"
)
