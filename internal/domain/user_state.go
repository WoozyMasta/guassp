// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package domain

// GitLabUserStateClass describes whether a GitLab user state is known.
type GitLabUserStateClass string

const (
	// GitLabUserStateUnknown is a missing or unsupported GitLab user state.
	GitLabUserStateUnknown GitLabUserStateClass = "unknown"
	// GitLabUserStateActive is the normal active GitLab user state.
	GitLabUserStateActive GitLabUserStateClass = "active"
	// GitLabUserStateInactive is a known blocked or deactivated GitLab state.
	GitLabUserStateInactive GitLabUserStateClass = "inactive"
)

// ClassifyGitLabUserState classifies only explicitly supported GitLab states.
func ClassifyGitLabUserState(state string) GitLabUserStateClass {
	switch state {
	case "active":
		return GitLabUserStateActive

	case "blocked", "banned", "deactivated", "ldap_blocked", "blocked_pending_approval":
		return GitLabUserStateInactive

	default:
		return GitLabUserStateUnknown
	}
}
