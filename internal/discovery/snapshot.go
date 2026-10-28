// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package discovery

import (
	"slices"
	"time"
)

// RefreshedAt returns the completion time of the successful discovery cycle.
func (snapshot *Snapshot) RefreshedAt() time.Time {
	if snapshot == nil {
		return time.Time{}
	}

	return snapshot.refreshedAt
}

// Projects returns all SonarQube projects bound to one GitLab project.
func (snapshot *Snapshot) Projects(gitLabProjectID int64) []Project {
	if snapshot == nil {
		return nil
	}

	projects := make([]Project, 0, len(snapshot.byGitLabProject[gitLabProjectID]))
	for _, record := range snapshot.byGitLabProject[gitLabProjectID] {
		projects = append(projects, record.Project)
	}

	return projects
}

// Bindings returns all binding records for one GitLab project.
func (snapshot *Snapshot) Bindings(gitLabProjectID int64) []BindingRecord {
	if snapshot == nil {
		return nil
	}

	return append([]BindingRecord(nil), snapshot.byGitLabProject[gitLabProjectID]...)
}

// Binding returns the record indexed by SonarQube project key.
func (snapshot *Snapshot) Binding(sonarProjectKey string) (BindingRecord, bool) {
	if snapshot == nil {
		return BindingRecord{}, false
	}

	record, exists := snapshot.bySonarProjectKey[sonarProjectKey]
	return record, exists
}

// GitLabProjectIDs returns sorted unique GitLab project IDs in the snapshot.
func (snapshot *Snapshot) GitLabProjectIDs() []int64 {
	if snapshot == nil {
		return nil
	}

	projectIDs := make([]int64, 0, len(snapshot.byGitLabProject))
	for projectID := range snapshot.byGitLabProject {
		projectIDs = append(projectIDs, projectID)
	}
	slices.Sort(projectIDs)

	return projectIDs
}

// Warnings returns a defensive copy of the diagnostics from the refresh.
func (snapshot *Snapshot) Warnings() []Warning {
	if snapshot == nil {
		return nil
	}

	return append([]Warning(nil), snapshot.warnings...)
}
