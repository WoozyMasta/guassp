// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package reconcile

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/woozymasta/guassp/internal/discovery"
	"github.com/woozymasta/guassp/internal/domain"
	"github.com/woozymasta/guassp/internal/gitlab"
	"github.com/woozymasta/guassp/internal/httpclient"
	"github.com/woozymasta/guassp/internal/sonar"
)

func (reconciler *Reconciler) reconcileTarget(
	ctx context.Context,
	gitLabProject gitlab.Project,
	target discovery.Project,
	desired map[string]domain.PermissionSet,
	protected map[string]struct{},
	users map[string]sonar.User,
	result *Result,
) targetStages {
	stages := targetStages{}
	started := time.Now()
	if event := reconciler.logger.Trace(); event.Enabled() {
		event.Str("operation", "reconcile SonarQube target").
			Int64("gitlab_project_id", gitLabProject.ID).
			Str("gitlab_project_path", gitLabProject.PathWithNamespace).
			Str("sonar_project_key", target.Key).
			Msg("SonarQube target reconciliation started")
	}
	defer func() {
		if event := reconciler.logger.Trace(); event.Enabled() {
			event.Str("operation", "reconcile SonarQube target").
				Int64("gitlab_project_id", gitLabProject.ID).
				Str("sonar_project_key", target.Key).
				Dur("duration", time.Since(started)).
				Str("permissions", string(stages.Permissions)).
				Str("visibility", string(stages.Visibility)).
				Msg("SonarQube target reconciliation finished")
		}
	}()

	currentPermissions, err := reconciler.sonar.DirectUserPermissions(ctx, target.Key)
	if err != nil {
		reconciler.addError(result, "read SonarQube direct permissions", err)
		stages.Permissions = StageFailed
	} else {
		current := currentPermissionsByLogin(currentPermissions)
		stages.Permissions = reconciler.applyPermissionDiff(
			ctx,
			target.Key,
			current,
			desired,
			protected,
			users,
			result,
		)
	}

	targetVisibility, applyVisibility, err := reconciler.visibility.Resolve(
		domain.GitLabVisibility(gitLabProject.Visibility),
	)
	switch {
	case err != nil:
		reconciler.addError(result, "resolve project visibility", err)
		stages.Visibility = StageFailed

	case !applyVisibility:
		stages.Visibility = StageSkipped

	default:
		currentVisibility, readErr := reconciler.sonar.ProjectVisibility(ctx, target.Key)
		if readErr != nil {
			reconciler.addError(result, "read SonarQube project visibility", readErr)
			stages.Visibility = StageFailed
		} else if targetVisibility == domain.SonarVisibility(currentVisibility) {
			stages.Visibility = StageSuccess
		} else if err := reconciler.sonar.UpdateProjectVisibility(ctx, target.Key, string(targetVisibility)); err != nil {
			reconciler.observePermission("visibility", "visibility", "failed")
			reconciler.addError(result, "update SonarQube project visibility", err)
			stages.Visibility = StageFailed
		} else {
			reconciler.observePermission("visibility", "visibility", "success")
			stages.Visibility = StageSuccess
		}
	}

	return stages
}

// applyPermissionDiff applies sorted grants and revokes for eligible logins.
func (reconciler *Reconciler) applyPermissionDiff(
	ctx context.Context,
	projectKey string,
	current map[string]domain.PermissionSet,
	desired map[string]domain.PermissionSet,
	protected map[string]struct{},
	users map[string]sonar.User,
	result *Result,
) StageStatus {
	var grants []permissionChange
	var revokes []permissionChange
	var succeeded, failed int

	logins := make(map[string]struct{}, len(current)+len(desired))
	for login := range current {
		logins[login] = struct{}{}
	}
	for login := range desired {
		logins[login] = struct{}{}
	}

	sortedLogins := make([]string, 0, len(logins))
	for login := range logins {
		sortedLogins = append(sortedLogins, login)
	}
	slices.Sort(sortedLogins)

	for _, login := range sortedLogins {
		if _, excluded := protected[login]; excluded {
			continue
		}

		user, known := users[login]
		if !known || user.ExternalProvider != "gitlab" || containsGroup(user.Groups, reconciler.matcher.skipGroups) {
			continue
		}

		diff := domain.DiffPermissions(current[login], desired[login], reconciler.managedPermissions)
		for _, permission := range diff.Grant.Sorted() {
			grants = append(grants, permissionChange{login: login, permission: permission})
		}
		for _, permission := range diff.Revoke.Sorted() {
			revokes = append(revokes, permissionChange{login: login, permission: permission})
		}
	}

	for _, change := range grants {
		if err := reconciler.sonar.GrantUserPermission(
			ctx,
			change.login,
			change.permission,
			projectKey,
		); err != nil {
			reconciler.observePermission("grant", change.permission, "failed")
			reconciler.addError(result, "grant SonarQube user permission", err)
			failed++
			continue
		}

		reconciler.observePermission("grant", change.permission, "success")
		result.Counts.Grants++
		succeeded++
	}

	for _, change := range revokes {
		if err := reconciler.sonar.RevokeUserPermission(
			ctx,
			change.login,
			change.permission,
			projectKey,
		); err != nil {
			reconciler.observePermission("revoke", change.permission, "failed")
			reconciler.addError(result, "revoke SonarQube user permission", err)
			failed++
			continue
		}

		reconciler.observePermission("revoke", change.permission, "success")
		result.Counts.Revokes++
		succeeded++
	}

	return operationStatus(succeeded, failed)
}

// deactivateUsers deactivates each still-active matched SonarQube user once.
func (reconciler *Reconciler) deactivateUsers(
	ctx context.Context,
	candidates map[string]sonar.User,
	result *Result,
) StageResult {
	var stages StageResult
	if len(candidates) == 0 {
		recordStage(&stages, StageSkipped)
		return stages
	}

	logins := make([]string, 0, len(candidates))
	for login := range candidates {
		logins = append(logins, login)
	}

	slices.Sort(logins)
	for _, login := range logins {
		if err := reconciler.sonar.DeactivateUser(ctx, candidates[login]); err != nil {
			reconciler.observePermission("deactivate", "deactivate", "failed")
			reconciler.addError(result, "deactivate SonarQube user", err)
			recordStage(&stages, StageFailed)
			continue
		}

		reconciler.observePermission("deactivate", "deactivate", "success")
		result.Counts.Deactivations++
		recordStage(&stages, StageSuccess)
	}

	return stages
}

// observePermission reports an operation when an observer was configured.
func (reconciler *Reconciler) observePermission(action, permission, result string) {
	if reconciler.permissionObserver != nil {
		reconciler.permissionObserver.ObservePermission(action, permission, result)
	}
}

// addError records an operation without exposing arbitrary upstream error text.
func (reconciler *Reconciler) addError(result *Result, operation string, err error) {
	result.Counts.Errors++
	result.Errors = append(result.Errors, operationError(operation, err))
}

// operationError keeps typed upstream errors and known context errors sanitized.
func operationError(operation string, err error) string {
	var apiError *httpclient.Error
	switch {
	case errors.As(err, &apiError):
		return operation + ": " + apiError.Error()

	case errors.Is(err, context.Canceled):
		return operation + ": context canceled"

	case errors.Is(err, context.DeadlineExceeded):
		return operation + ": deadline exceeded"

	default:
		return operation + ": request failed"
	}
}

// usersByLogin merges duplicate records so group exclusions remain conservative.
func usersByLogin(users []sonar.User) map[string]sonar.User {
	byLogin := make(map[string]sonar.User, len(users))
	for _, user := range users {
		if user.Login == "" {
			continue
		}

		mergeSonarUser(byLogin, user)
	}

	return byLogin
}

// mergeSonarUser combines duplicate account records without relaxing exclusions.
func mergeSonarUser(users map[string]sonar.User, user sonar.User) {
	if user.Login == "" {
		return
	}

	if existing, exists := users[user.Login]; exists {
		existing.Groups = append(existing.Groups, user.Groups...)
		if existing.ExternalProvider != user.ExternalProvider {
			existing.ExternalProvider = ""
		}
		if existing.ExternalIdentity != user.ExternalIdentity {
			existing.ExternalIdentity = ""
		}

		existing.Active = existing.Active && user.Active
		users[user.Login] = existing
		return
	}

	users[user.Login] = user
}

// currentPermissionsByLogin merges direct permission records by SonarQube login.
func currentPermissionsByLogin(records []sonar.UserPermissions) map[string]domain.PermissionSet {
	current := make(map[string]domain.PermissionSet, len(records))
	for _, record := range records {
		if record.Login == "" {
			continue
		}

		permissions := current[record.Login]
		if permissions == nil {
			permissions = make(domain.PermissionSet)
			current[record.Login] = permissions
		}
		for _, permission := range record.Permissions {
			permissions[permission] = struct{}{}
		}
	}

	return current
}

// protectIdentityUsers excludes matching GitLab-backed accounts from stale revokes.
func protectIdentityUsers(protected map[string]struct{}, users []sonar.User, member gitlab.Member) {
	identity := identityForMember(member)
	for _, user := range users {
		if user.ExternalProvider == "gitlab" && identity.matches(user.ExternalIdentity) {
			protected[user.Login] = struct{}{}
		}
	}
}

// mergePermissionSets adds source permissions to a destination set.
func mergePermissionSets(destination, source domain.PermissionSet) {
	for permission := range source {
		destination[permission] = struct{}{}
	}
}

// clonePermissionMap copies the map and each permission set.
func clonePermissionMap(source domain.PermissionMap) domain.PermissionMap {
	clone := make(domain.PermissionMap, len(source))
	for level, permissions := range source {
		clone[level] = permissions.Clone()
	}

	return clone
}
