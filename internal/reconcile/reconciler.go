// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package reconcile

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/woozymasta/guassp/internal/discovery"
	"github.com/woozymasta/guassp/internal/domain"
	"github.com/woozymasta/guassp/internal/gitlab"
	"github.com/woozymasta/guassp/internal/httpclient"
	"github.com/woozymasta/guassp/internal/sonar"
)

// NewReconciler creates a reconciler with copied policy values.
func NewReconciler(
	gitlabClient GitLabSource,
	sonarClient SonarTarget,
	targetDiscovery TargetDiscovery,
	directory *UserDirectory,
	matcher *UserMatcher,
	options Options,
) (*Reconciler, error) {
	if gitlabClient == nil || sonarClient == nil || targetDiscovery == nil {
		return nil, errors.New("GitLab, SonarQube, and discovery clients are required")
	}

	if directory == nil || matcher == nil {
		return nil, errors.New("SonarQube user directory and matcher are required")
	}

	if observer, ok := options.PermissionObserver.(httpclient.RequestObserver); ok {
		if client, supportsObservation := gitlabClient.(interface {
			SetObserver(httpclient.RequestObserver)
		}); supportsObservation {
			client.SetObserver(observer)
		}
		if client, supportsObservation := sonarClient.(interface {
			SetObserver(httpclient.RequestObserver)
		}); supportsObservation {
			client.SetObserver(observer)
		}
	}

	if options.PermissionMap == nil {
		options.PermissionMap = domain.DefaultPermissionMap()
	}
	if options.Visibility.Mode == "" {
		options.Visibility = domain.VisibilityPolicy{
			Mode:    domain.VisibilityMap,
			Mapping: domain.DefaultVisibilityMap(),
		}
	}

	if options.Visibility.Mode != domain.VisibilityMap &&
		options.Visibility.Mode != domain.VisibilityIgnore {
		return nil, errors.New("unsupported visibility mode")
	}

	if options.Visibility.Mapping == nil && options.Visibility.Mode == domain.VisibilityMap {
		options.Visibility.Mapping = domain.DefaultVisibilityMap()
	}
	if options.DiscoveryMode == "" {
		options.DiscoveryMode = domain.ProjectDiscoveryBinding
	}
	if options.DiscoveryMode != domain.ProjectDiscoveryBinding &&
		options.DiscoveryMode != domain.ProjectDiscoveryBindingPathFallback {
		return nil, errors.New("unsupported project discovery mode")
	}

	permissionMap := clonePermissionMap(options.PermissionMap)
	visibilityMap := make(map[domain.GitLabVisibility]domain.SonarVisibility, len(options.Visibility.Mapping))
	maps.Copy(visibilityMap, options.Visibility.Mapping)
	skipGitLabUsers := make(map[int64]struct{}, len(options.SkipGitLabUsers))
	for _, userID := range options.SkipGitLabUsers {
		if userID > 0 {
			skipGitLabUsers[userID] = struct{}{}
		}
	}

	return &Reconciler{
		logger:               options.Logger.With().Str("component", "reconcile").Logger(),
		gitlab:               gitlabClient,
		sonar:                sonarClient,
		discovery:            targetDiscovery,
		directory:            directory,
		matcher:              matcher,
		permissionMap:        permissionMap,
		managedPermissions:   permissionMap.ManagedPermissions(),
		visibility:           domain.VisibilityPolicy{Mode: options.Visibility.Mode, Mapping: visibilityMap},
		discoveryMode:        options.DiscoveryMode,
		skipGitLabUsers:      skipGitLabUsers,
		syncUserDeactivation: options.SyncUserDeactivation,
		permissionObserver:   options.PermissionObserver,
	}, nil
}

// Reconcile computes and applies the desired access state for one GitLab project.
func (reconciler *Reconciler) Reconcile(ctx context.Context, projectID int64) Result {
	started := time.Now()
	result := Result{ProjectID: projectID, Stages: newStageResults()}
	defer func() { reconciler.logResult(result, started) }()
	if event := reconciler.logger.Trace(); event.Enabled() {
		event.Str("operation", "reconcile project").
			Int64("gitlab_project_id", projectID).
			Msg("reconciliation started")
	}
	if projectID < 1 {
		reconciler.addError(&result, "validate GitLab project ID", errors.New("project ID must be positive"))
		result.Status = StatusFailed
		return result
	}

	project, err := reconciler.gitlab.Project(ctx, strconv.FormatInt(projectID, 10))
	if err != nil {
		reconciler.addError(&result, "get GitLab project", err)
		result.Status = StatusFailed
		return result
	}

	if project.ID != projectID {
		reconciler.addError(&result, "validate GitLab project response", errors.New("project ID mismatch"))
		result.Status = StatusFailed
		return result
	}

	result.GitLabProject = project.PathWithNamespace
	if event := reconciler.logger.Debug(); event.Enabled() {
		event.Str("operation", "reconcile project").
			Int64("gitlab_project_id", projectID).
			Str("gitlab_project_path", project.PathWithNamespace).
			Msg("loaded GitLab project")
	}

	targets, err := reconciler.discovery.Lookup(ctx, projectID)
	if err != nil {
		reconciler.addError(&result, "discover SonarQube targets", err)
		result.Status = StatusFailed
		return result
	}

	legacyFallback := false
	if len(targets) == 0 && reconciler.discoveryMode == domain.ProjectDiscoveryBindingPathFallback {
		target, found, fallbackErr := reconciler.discovery.LegacyPathFallback(ctx, project.PathWithNamespace)
		if fallbackErr != nil {
			reconciler.addError(&result, "search legacy SonarQube target", fallbackErr)
			result.Status = StatusFailed
			return result
		}

		if found {
			targets = []discovery.Project{target}
			legacyFallback = true
		} else {
			result.Warnings = append(result.Warnings, "legacy SonarQube target has no unique exact name match")
		}
	}

	if !legacyFallback {
		verifiedTargets := make([]discovery.Project, 0, len(targets))
		for _, target := range targets {
			if target.BindingStale {
				result.Warnings = append(result.Warnings, "SonarQube project binding came from a stale discovery hint")
			}
			verified, verifyErr := reconciler.discovery.VerifyBinding(ctx, projectID, target.Key)
			if verifyErr != nil {
				reconciler.addError(&result, "verify SonarQube project binding", verifyErr)
				continue
			}

			if !verified {
				result.Warnings = append(result.Warnings, "SonarQube project binding changed; target skipped")
				continue
			}

			verifiedTargets = append(verifiedTargets, target)
		}
		targets = verifiedTargets
	}

	if len(targets) == 0 {
		switch {
		case result.Counts.Errors > 0:
			result.Status = StatusFailed

		case len(result.Warnings) > 0:
			result.Status = StatusPartial

		default:
			result.Status = StatusSkipped
		}

		return result
	}

	slices.SortFunc(targets, func(left, right discovery.Project) int {
		return strings.Compare(left.Key, right.Key)
	})

	result.Counts.Targets = len(targets)
	if event := reconciler.logger.Debug(); event.Enabled() {
		event.Str("operation", "discover SonarQube targets").
			Int64("gitlab_project_id", projectID).
			Int("target_count", len(targets)).
			Msg("resolved SonarQube targets")
	}

	result.SonarProjects = make([]string, len(targets))
	for index, target := range targets {
		result.SonarProjects[index] = target.Key
	}

	members, err := reconciler.gitlab.ProjectMembers(ctx, projectID)
	if err != nil {
		reconciler.addError(&result, "list GitLab project members", err)
		result.Status = StatusFailed
		return result
	}

	result.Counts.Members = len(members)
	if event := reconciler.logger.Debug(); event.Enabled() {
		event.Str("operation", "list GitLab project members").
			Int64("gitlab_project_id", projectID).
			Int("member_count", len(members)).
			Msg("loaded GitLab project members")
	}

	directoryUsers, err := reconciler.directory.Snapshot(ctx)
	if err != nil {
		reconciler.addError(&result, "load SonarQube user directory", err)
		result.Status = StatusFailed
		return result
	}

	users := usersByLogin(directoryUsers)
	desired, protected, deactivationCandidates := reconciler.desiredUsers(
		ctx,
		members,
		directoryUsers,
		users,
		&result,
	)

	for _, target := range targets {
		targetResult := reconciler.reconcileTarget(ctx, project, target, desired, protected, users, &result)
		recordStage(&result.Stages.Permissions, targetResult.Permissions)
		recordStage(&result.Stages.Visibility, targetResult.Visibility)
	}
	if reconciler.syncUserDeactivation {
		result.Stages.Deactivation = reconciler.deactivateUsers(ctx, deactivationCandidates, &result)
	} else {
		recordStage(&result.Stages.Deactivation, StageSkipped)
	}

	result.Status = summarizeResult(result)

	return result
}

// logResult records one bounded aggregate result without user identities.
func (reconciler *Reconciler) logResult(result Result, started time.Time) {
	event := reconciler.logger.Debug()
	if !event.Enabled() {
		return
	}

	event.Str("operation", "reconcile project").
		Int64("gitlab_project_id", result.ProjectID).
		Str("gitlab_project_path", result.GitLabProject).
		Dur("duration", time.Since(started)).
		Str("result", string(result.Status)).
		Int("targets", result.Counts.Targets).
		Int("members", result.Counts.Members).
		Int("matched", result.Counts.Matched).
		Int("unmatched", result.Counts.Unmatched).
		Int("grants", result.Counts.Grants).
		Int("revokes", result.Counts.Revokes).
		Int("mapping_misses", result.Counts.MappingMisses).
		Int("unknown_user_states", result.Counts.UnknownUserStates).
		Int("errors", result.Counts.Errors).
		Msg("reconciliation completed")
}

// desiredUsers matches current GitLab members and resolves their desired permissions.
func (reconciler *Reconciler) desiredUsers(
	ctx context.Context,
	members []gitlab.Member,
	directoryUsers []sonar.User,
	users map[string]sonar.User,
	result *Result,
) (map[string]domain.PermissionSet, map[string]struct{}, map[string]sonar.User) {
	desired := make(map[string]domain.PermissionSet)
	protected := make(map[string]struct{})
	deactivationCandidates := make(map[string]sonar.User)
	slices.SortFunc(members, func(left, right gitlab.Member) int {
		if comparison := cmp.Compare(left.ID, right.ID); comparison != 0 {
			return comparison
		}

		return cmp.Compare(left.Username, right.Username)
	})

	for _, member := range members {
		if _, skipped := reconciler.skipGitLabUsers[member.ID]; skipped {
			result.Counts.SkippedUsers++
			protectIdentityUsers(protected, directoryUsers, member)
			continue
		}

		stateClass := domain.ClassifyGitLabUserState(member.State)
		if stateClass == domain.GitLabUserStateUnknown {
			result.Counts.UnknownUserStates++
			result.Warnings = append(result.Warnings, "GitLab member has a missing or unsupported state")
		}

		matched, err := reconciler.matcher.Match(ctx, member)
		if err != nil {
			result.Counts.Errors++
			result.Errors = append(result.Errors, operationError("match GitLab member", err))
			protectIdentityUsers(protected, directoryUsers, member)
			continue
		}

		switch matched.Status {
		case MatchUnmatched:
			result.Counts.Unmatched++
			protectIdentityUsers(protected, directoryUsers, member)
			continue

		case MatchAmbiguous:
			result.Counts.Ambiguous++
			result.Warnings = append(result.Warnings, "multiple SonarQube users match a GitLab identity")
			protectIdentityUsers(protected, directoryUsers, member)
			for _, user := range matched.Candidates {
				mergeSonarUser(users, user)
				protected[user.Login] = struct{}{}
			}
			continue

		case MatchSkipped:
			result.Counts.SkippedUsers++
			mergeSonarUser(users, matched.User)
			protected[matched.User.Login] = struct{}{}
			continue

		case MatchMatched:
			result.Counts.Matched++
			mergeSonarUser(users, matched.User)

		default:
			result.Counts.Errors++
			result.Errors = append(result.Errors, "match GitLab member: unsupported match result")
			protectIdentityUsers(protected, directoryUsers, member)
			continue
		}

		if !matched.User.Active {
			result.Counts.SkippedUsers++
			protected[matched.User.Login] = struct{}{}
			continue
		}

		switch stateClass {
		case domain.GitLabUserStateInactive:
			if reconciler.syncUserDeactivation {
				deactivationCandidates[matched.User.Login] = matched.User
			}

			continue

		case domain.GitLabUserStateUnknown:
			protected[matched.User.Login] = struct{}{}
			continue
		}

		permissions, exists := reconciler.permissionMap.ForAccessLevel(domain.AccessLevel(member.AccessLevel))
		if !exists {
			result.Counts.MappingMisses++
			result.Warnings = append(result.Warnings, "GitLab member access level has no permission mapping")
			protected[matched.User.Login] = struct{}{}
			continue
		}

		if existing, exists := desired[matched.User.Login]; exists {
			mergePermissionSets(existing, permissions)
		} else {
			desired[matched.User.Login] = permissions
		}
	}

	for login := range desired {
		delete(deactivationCandidates, login)
	}
	for login := range protected {
		delete(deactivationCandidates, login)
	}

	return desired, protected, deactivationCandidates
}
