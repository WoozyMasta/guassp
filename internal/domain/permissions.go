// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

// Package domain contains pure synchronization policies and value types.
package domain

import "sort"

// AccessLevel is a positive GitLab project access level.
type AccessLevel int

// PermissionSet stores distinct SonarQube permission names.
type PermissionSet map[string]struct{}

// Has reports whether the set contains permission.
func (permissions PermissionSet) Has(permission string) bool {
	_, exists := permissions[permission]
	return exists
}

// Clone returns an independent copy of the set.
func (permissions PermissionSet) Clone() PermissionSet {
	clone := make(PermissionSet, len(permissions))
	for permission := range permissions {
		clone[permission] = struct{}{}
	}

	return clone
}

// Sorted returns the set values in lexical order.
func (permissions PermissionSet) Sorted() []string {
	values := make([]string, 0, len(permissions))
	for permission := range permissions {
		values = append(values, permission)
	}
	sort.Strings(values)

	return values
}

// PermissionMap maps exact GitLab access levels to SonarQube permissions.
type PermissionMap map[AccessLevel]PermissionSet

// DefaultPermissionMap returns the legacy-compatible access-level mapping.
func DefaultPermissionMap() PermissionMap {
	mapping := make(PermissionMap, 5)
	permissions := make(PermissionSet)
	add := func(level AccessLevel, added ...string) {
		for _, permission := range added {
			permissions[permission] = struct{}{}
		}
		mapping[level] = permissions.Clone()
	}

	add(10, "user")
	add(20, "codeviewer")
	add(30, "issueadmin")
	add(40, "securityhotspotadmin")
	add(50, "admin")

	return mapping
}

// NewPermissionSet creates a set from permission names.
func NewPermissionSet(permissions ...string) PermissionSet {
	set := make(PermissionSet, len(permissions))
	for _, permission := range permissions {
		set[permission] = struct{}{}
	}

	return set
}

// ForAccessLevel returns permissions for an exact access-level mapping.
func (mapping PermissionMap) ForAccessLevel(level AccessLevel) (PermissionSet, bool) {
	permissions, exists := mapping[level]
	if !exists {
		return nil, false
	}

	return permissions.Clone(), true
}

// ManagedPermissions returns the union of permissions in every mapping.
func (mapping PermissionMap) ManagedPermissions() PermissionSet {
	managed := make(PermissionSet)
	for _, permissions := range mapping {
		for permission := range permissions {
			managed[permission] = struct{}{}
		}
	}

	return managed
}

// PermissionDiff contains the permission writes needed to reach desired state.
type PermissionDiff struct {
	// Grant contains managed permissions missing from current state.
	Grant PermissionSet
	// Revoke contains managed permissions absent from desired state.
	Revoke PermissionSet
}

// DiffPermissions computes grants and revokes without touching unmanaged values.
func DiffPermissions(current, desired, managed PermissionSet) PermissionDiff {
	diff := PermissionDiff{
		Grant:  make(PermissionSet),
		Revoke: make(PermissionSet),
	}

	for permission := range managed {
		_, isCurrent := current[permission]
		_, isDesired := desired[permission]

		switch {
		case isDesired && !isCurrent:
			diff.Grant[permission] = struct{}{}

		case isCurrent && !isDesired:
			diff.Revoke[permission] = struct{}{}
		}
	}

	return diff
}
