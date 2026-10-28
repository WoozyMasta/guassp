// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package domain

import "testing"

func TestClassifyGitLabUserState(t *testing.T) {
	tests := []struct {
		state string
		want  GitLabUserStateClass
	}{
		{state: "active", want: GitLabUserStateActive},
		{state: "blocked", want: GitLabUserStateInactive},
		{state: "banned", want: GitLabUserStateInactive},
		{state: "deactivated", want: GitLabUserStateInactive},
		{state: "ldap_blocked", want: GitLabUserStateInactive},
		{state: "blocked_pending_approval", want: GitLabUserStateInactive},
		{state: "", want: GitLabUserStateUnknown},
		{state: "future_state", want: GitLabUserStateUnknown},
		{state: " Active ", want: GitLabUserStateUnknown},
	}

	for _, test := range tests {
		t.Run(test.state, func(t *testing.T) {
			if got := ClassifyGitLabUserState(test.state); got != test.want {
				t.Fatalf("ClassifyGitLabUserState(%q) = %q, want %q", test.state, got, test.want)
			}
		})
	}
}
