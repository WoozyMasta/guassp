// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package domain

import (
	"slices"
	"testing"
)

func TestDefaultPermissionMapUsesExactAccessLevels(t *testing.T) {
	mapping := DefaultPermissionMap()
	tests := []struct {
		level AccessLevel
		want  []string
	}{
		{level: 10, want: []string{"user"}},
		{level: 20, want: []string{"codeviewer", "user"}},
		{level: 30, want: []string{"codeviewer", "issueadmin", "user"}},
		{level: 40, want: []string{"codeviewer", "issueadmin", "securityhotspotadmin", "user"}},
		{level: 50, want: []string{"admin", "codeviewer", "issueadmin", "securityhotspotadmin", "user"}},
	}

	for _, test := range tests {
		got, ok := mapping.ForAccessLevel(test.level)
		if !ok || !slices.Equal(got.Sorted(), test.want) {
			t.Errorf("ForAccessLevel(%d) = %v, want %v", test.level, got.Sorted(), test.want)
		}
	}
	for _, level := range []AccessLevel{9, 15, 19, 25, 29, 49, 51} {
		if _, ok := mapping.ForAccessLevel(level); ok {
			t.Errorf("ForAccessLevel(%d) unexpectedly found a mapping", level)
		}
	}
}

func TestPermissionMapDistinguishesMissingAndExplicitEmpty(t *testing.T) {
	mapping := PermissionMap{
		15: NewPermissionSet("planner"),
		25: {},
	}

	got, exists := mapping.ForAccessLevel(15)
	if !exists || !slices.Equal(got.Sorted(), []string{"planner"}) {
		t.Fatalf("ForAccessLevel(15) = %v, %t", got.Sorted(), exists)
	}

	got, exists = mapping.ForAccessLevel(25)
	if !exists || len(got) != 0 {
		t.Fatalf("ForAccessLevel(25) = %v, %t; want explicit empty mapping", got, exists)
	}

	if got, exists := mapping.ForAccessLevel(24); exists || got != nil {
		t.Fatalf("ForAccessLevel(24) = %v, %t; want mapping miss", got, exists)
	}
}

func TestManagedPermissionsAndDiffPreserveUnknownValues(t *testing.T) {
	managed := DefaultPermissionMap().ManagedPermissions()
	if managed.Has("scan") || managed.Has("unexpected") {
		t.Fatalf("managed permissions = %v", managed.Sorted())
	}

	diff := DiffPermissions(
		NewPermissionSet("user", "codeviewer", "scan", "unexpected"),
		NewPermissionSet("user", "issueadmin", "unconfigured"),
		managed,
	)
	if got, want := diff.Grant.Sorted(), []string{"issueadmin"}; !slices.Equal(got, want) {
		t.Errorf("grants = %v, want %v", got, want)
	}
	if got, want := diff.Revoke.Sorted(), []string{"codeviewer"}; !slices.Equal(got, want) {
		t.Errorf("revokes = %v, want %v", got, want)
	}
}
