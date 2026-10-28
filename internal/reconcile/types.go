// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package reconcile

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/woozymasta/guassp/internal/discovery"
	"github.com/woozymasta/guassp/internal/domain"
	"github.com/woozymasta/guassp/internal/gitlab"
	"github.com/woozymasta/guassp/internal/sonar"
)

// GitLabSource provides project and effective-member reads for reconciliation.
type GitLabSource interface {
	Project(context.Context, string) (gitlab.Project, error)
	ProjectMembers(context.Context, int64) ([]gitlab.Member, error)
}

// SonarTarget provides direct-permission reads and project/user writes.
type SonarTarget interface {
	DirectUserPermissions(context.Context, string) ([]sonar.UserPermissions, error)
	ProjectVisibility(context.Context, string) (string, error)
	GrantUserPermission(context.Context, string, string, string) error
	RevokeUserPermission(context.Context, string, string, string) error
	UpdateProjectVisibility(context.Context, string, string) error
	DeactivateUser(context.Context, sonar.User) error
}

// TargetDiscovery resolves SonarQube targets associated with a GitLab project.
type TargetDiscovery interface {
	Lookup(context.Context, int64) ([]discovery.Project, error)
	LegacyPathFallback(context.Context, string) (discovery.Project, bool, error)
	VerifyBinding(context.Context, int64, string) (bool, error)
}

// Options configures the permission, visibility, discovery, and user policies.
type Options struct {
	// Logger records safe reconciliation milestones when trace or debug is enabled.
	Logger zerolog.Logger
	// PermissionObserver records bounded permission operation outcomes.
	PermissionObserver PermissionObserver
	// PermissionMap maps GitLab access levels to managed SonarQube permissions.
	PermissionMap domain.PermissionMap
	// Visibility selects how GitLab visibility is applied to SonarQube.
	Visibility domain.VisibilityPolicy
	// DiscoveryMode selects explicit bindings or the legacy path fallback.
	DiscoveryMode domain.ProjectDiscoveryMode
	// SkipGitLabUsers excludes these GitLab IDs from matching and permission writes.
	SkipGitLabUsers []int64
	// SyncUserDeactivation enables global deactivation for explicitly inactive members.
	SyncUserDeactivation bool
}

// PermissionObserver records one permission, visibility, or lifecycle operation.
type PermissionObserver interface {
	// ObservePermission records the action, permission class, and result.
	ObservePermission(action, permission, result string)
}

// Status describes the completion state of one project reconciliation.
type Status string

const (
	// StatusSuccess means applicable work completed without errors or warnings.
	StatusSuccess Status = "success"
	// StatusPartial means useful work completed alongside errors or warnings.
	StatusPartial Status = "partial"
	// StatusFailed means reconciliation could not complete its core work.
	StatusFailed Status = "failed"
	// StatusSkipped means no SonarQube target was found.
	StatusSkipped Status = "skipped"
)

// StageStatus describes the outcome of one reconciliation stage.
type StageStatus string

const (
	// StageNotRun means the stage was not reached.
	StageNotRun StageStatus = "not_run"
	// StageSuccess means all attempted stage units succeeded.
	StageSuccess StageStatus = "success"
	// StagePartial means stage units had mixed outcomes or one unit had mixed operations.
	StagePartial StageStatus = "partial"
	// StageFailed means every attempted stage unit failed.
	StageFailed StageStatus = "failed"
	// StageSkipped means policy or discovery skipped the stage.
	StageSkipped StageStatus = "skipped"
)

// StageResult summarizes outcomes for one reconciliation stage.
type StageResult struct {
	// Status is the aggregate outcome across attempted units.
	Status StageStatus `json:"status"`
	// Attempts is the number of targets or users processed.
	Attempts int `json:"attempts"`
	// Succeeded is the number of units completed without errors.
	Succeeded int `json:"succeeded"`
	// Partial is the number of units with both successful and failed operations.
	Partial int `json:"partial"`
	// Failed is the number of units that did not complete.
	Failed int `json:"failed"`
	// Skipped is the number of units omitted by policy or unavailable inputs.
	Skipped int `json:"skipped"`
}

// StageResults contains independent outcomes for reconciliation side effects.
type StageResults struct {
	// Permissions summarizes direct project permission reconciliation.
	Permissions StageResult `json:"permissions"`
	// Visibility summarizes project visibility reconciliation.
	Visibility StageResult `json:"visibility"`
	// Deactivation summarizes optional global user deactivation.
	Deactivation StageResult `json:"deactivation"`
}

// Counts summarizes member decisions and successful permission/user writes.
type Counts struct {
	// Members is the number of effective GitLab project members returned.
	Members int `json:"members" yaml:"members"`
	// Matched is the number of members with one eligible SonarQube user.
	Matched int `json:"matched" yaml:"matched"`
	// Unmatched is the number of members with no eligible SonarQube user.
	Unmatched int `json:"unmatched" yaml:"unmatched"`
	// Ambiguous is the number of members matching multiple SonarQube logins.
	Ambiguous int `json:"ambiguous" yaml:"ambiguous"`
	// SkippedUsers is the number of members excluded by a configured policy.
	SkippedUsers int `json:"skipped_users" yaml:"skipped_users"`
	// MappingMisses is the number of access levels without an exact configured mapping.
	MappingMisses int `json:"mapping_misses" yaml:"mapping_misses"`
	// UnknownUserStates is the number of GitLab members with missing or unsupported states.
	UnknownUserStates int `json:"unknown_user_states" yaml:"unknown_user_states"`
	// Targets is the number of SonarQube projects processed.
	Targets int `json:"targets" yaml:"targets"`
	// Grants is the number of successful direct permission grants.
	Grants int `json:"grants" yaml:"grants"`
	// Revokes is the number of successful direct permission revocations.
	Revokes int `json:"revokes" yaml:"revokes"`
	// Deactivations is the number of successful global user deactivations.
	Deactivations int `json:"deactivations" yaml:"deactivations"`
	// Errors is the number of recorded operation errors.
	Errors int `json:"errors" yaml:"errors"`
}

// Result summarizes one GitLab project's reconciliation run.
type Result struct {
	// Status is the overall completion state.
	Status Status
	// GitLabProject is the canonical namespace path used for the run.
	GitLabProject string
	// Errors contains sanitized operation summaries.
	Errors []string
	// Warnings contains identity and policy warnings without user details.
	Warnings []string
	// SonarProjects contains the keys of the resolved SonarQube targets.
	SonarProjects []string
	// Stages contains independent permission, visibility, and lifecycle outcomes.
	Stages StageResults `json:"stages"`
	// Counts contains aggregate counts for the run.
	Counts Counts
	// ProjectID is the GitLab project ID used for the run.
	ProjectID int64
}

// Reconciler applies GitLab desired access to bound SonarQube projects.
type Reconciler struct {
	logger               zerolog.Logger
	gitlab               GitLabSource
	sonar                SonarTarget
	discovery            TargetDiscovery
	permissionObserver   PermissionObserver
	directory            *UserDirectory
	matcher              *UserMatcher
	permissionMap        domain.PermissionMap
	managedPermissions   domain.PermissionSet
	skipGitLabUsers      map[int64]struct{}
	visibility           domain.VisibilityPolicy
	discoveryMode        domain.ProjectDiscoveryMode
	syncUserDeactivation bool
}

// permissionChange identifies one direct permission operation for one user.
type permissionChange struct {
	login      string
	permission string
}
