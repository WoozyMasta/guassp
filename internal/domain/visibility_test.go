// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package domain

import "testing"

func TestVisibilityPolicyMap(t *testing.T) {
	policy := VisibilityPolicy{Mode: VisibilityMap, Mapping: DefaultVisibilityMap()}
	for source, want := range map[GitLabVisibility]SonarVisibility{
		"public":   "public",
		"internal": "private",
		"private":  "private",
	} {
		got, apply, err := policy.Resolve(source)
		if err != nil || !apply || got != want {
			t.Errorf("Resolve(%q) = %q, %t, %v; want %q, true, nil", source, got, apply, err, want)
		}
	}
}

func TestVisibilityPolicyModesAndErrors(t *testing.T) {
	tests := []struct {
		name    string
		policy  VisibilityPolicy
		source  GitLabVisibility
		want    SonarVisibility
		apply   bool
		wantErr bool
	}{
		{
			name:   "ignore",
			policy: VisibilityPolicy{Mode: VisibilityIgnore},
			source: "public",
		},
		{
			name: "invalid mapped target",
			policy: VisibilityPolicy{Mode: VisibilityMap, Mapping: map[GitLabVisibility]SonarVisibility{
				"public": "internal",
			}},
			source:  "public",
			wantErr: true,
		},
		{
			name:    "unsupported source",
			policy:  VisibilityPolicy{Mode: VisibilityMap, Mapping: DefaultVisibilityMap()},
			source:  "unknown",
			wantErr: true,
		},
		{
			name:    "missing mapping",
			policy:  VisibilityPolicy{Mode: VisibilityMap, Mapping: map[GitLabVisibility]SonarVisibility{}},
			source:  "public",
			wantErr: true,
		},
		{
			name:    "unsupported mode",
			policy:  VisibilityPolicy{Mode: "unknown"},
			source:  "public",
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, apply, err := test.policy.Resolve(test.source)
			if (err != nil) != test.wantErr || got != test.want || apply != test.apply {
				t.Fatalf("Resolve() = %q, %t, %v", got, apply, err)
			}
		})
	}
}
