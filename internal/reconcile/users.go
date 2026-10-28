// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

// Package reconcile contains identity and synchronization orchestration.
package reconcile

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/woozymasta/guassp/internal/sonar"
)

const userDirectoryTTL = time.Minute

// SonarUserSource loads the SonarQube user directory.
type SonarUserSource interface {
	Users(context.Context) ([]sonar.User, error)
}

// UserDirectory caches an indexed SonarQube user snapshot for one minute.
type UserDirectory struct {
	refreshedAt time.Time
	source      SonarUserSource
	snapshot    *userIndex
	now         func() time.Time
	mu          sync.RWMutex
	refreshMu   sync.Mutex
}

// userIndex stores one immutable snapshot and its matching indexes.
type userIndex struct {
	byLogin         map[string]sonar.User
	byExternalID    map[string][]sonar.User
	byEmail         map[string][]sonar.User
	byName          map[string][]sonar.User
	users           []sonar.User
	refreshedOnMiss bool
}

// NewUserDirectory creates an in-memory SonarQube user directory.
func NewUserDirectory(source SonarUserSource) (*UserDirectory, error) {
	if source == nil {
		return nil, errors.New("SonarQube user source is required")
	}

	return &UserDirectory{source: source, now: time.Now}, nil
}

// Snapshot returns a defensive copy of the cached or freshly loaded users.
func (directory *UserDirectory) Snapshot(ctx context.Context) ([]sonar.User, error) {
	index, err := directory.load(ctx, false)
	if err != nil {
		return nil, err
	}

	return cloneUsers(index.users), nil
}

// Refresh forces a serialized refresh and returns the complete new snapshot.
func (directory *UserDirectory) Refresh(ctx context.Context) ([]sonar.User, error) {
	index, err := directory.load(ctx, true)
	if err != nil {
		return nil, err
	}

	return cloneUsers(index.users), nil
}

// Lookup returns one user by SonarQube login from the current snapshot.
func (directory *UserDirectory) Lookup(ctx context.Context, login string) (sonar.User, bool, error) {
	index, err := directory.load(ctx, false)
	if err != nil {
		return sonar.User{}, false, err
	}

	user, exists := index.byLogin[login]
	if !exists {
		return sonar.User{}, false, nil
	}

	return cloneUser(user), true, nil
}

// load returns a valid snapshot, refreshing it when expired or explicitly forced.
func (directory *UserDirectory) load(ctx context.Context, force bool) (*userIndex, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !force {
		if index := directory.cached(); index != nil {
			return index, nil
		}
	}

	directory.refreshMu.Lock()
	defer directory.refreshMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !force {
		if index := directory.cached(); index != nil {
			return index, nil
		}
	}

	users, err := directory.source.Users(ctx)
	if err != nil {
		return nil, err
	}

	index := newUserIndex(users)
	index.refreshedOnMiss = force
	directory.mu.Lock()
	directory.snapshot = index
	directory.refreshedAt = directory.now()
	directory.mu.Unlock()

	return index, nil
}

// refreshOnMiss forces at most one refresh for a snapshot, coalescing concurrent misses.
func (directory *UserDirectory) refreshOnMiss(ctx context.Context, observed *userIndex) (*userIndex, error) {
	directory.refreshMu.Lock()
	defer directory.refreshMu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	directory.mu.RLock()
	current := directory.snapshot
	directory.mu.RUnlock()
	if current != observed || observed.refreshedOnMiss {
		if current != nil {
			return current, nil
		}
	}

	users, err := directory.source.Users(ctx)
	if err != nil {
		return nil, err
	}

	index := newUserIndex(users)
	index.refreshedOnMiss = true
	directory.mu.Lock()
	directory.snapshot = index
	directory.refreshedAt = directory.now()
	directory.mu.Unlock()

	return index, nil
}

// cached returns the snapshot only while it remains within the fixed TTL.
func (directory *UserDirectory) cached() *userIndex {
	directory.mu.RLock()
	defer directory.mu.RUnlock()
	if directory.snapshot == nil || directory.now().Sub(directory.refreshedAt) >= userDirectoryTTL {
		return nil
	}

	return directory.snapshot
}

// newUserIndex copies users and builds lookup indexes for one snapshot.
func newUserIndex(users []sonar.User) *userIndex {
	index := &userIndex{
		users:        cloneUsers(users),
		byLogin:      make(map[string]sonar.User, len(users)),
		byExternalID: make(map[string][]sonar.User),
		byEmail:      make(map[string][]sonar.User),
		byName:       make(map[string][]sonar.User),
	}

	for _, user := range index.users {
		if user.Login == "" {
			continue
		}

		if existing, exists := index.byLogin[user.Login]; exists {
			user.Groups = append(append([]string(nil), existing.Groups...), user.Groups...)
		}
		index.byLogin[user.Login] = user
		if user.ExternalProvider == "gitlab" && user.ExternalIdentity != "" {
			index.byExternalID[user.ExternalIdentity] = append(index.byExternalID[user.ExternalIdentity], user)
		}
		if email := normalizeEmail(user.Email); email != "" {
			index.byEmail[email] = append(index.byEmail[email], user)
		}
		if name := normalizeName(user.Name); name != "" {
			index.byName[name] = append(index.byName[name], user)
		}
	}

	return index
}

// cloneUsers prevents callers and source adapters from mutating cached slices.
func cloneUsers(users []sonar.User) []sonar.User {
	clones := make([]sonar.User, len(users))
	for index, user := range users {
		clones[index] = cloneUser(user)
	}

	return clones
}

// cloneUser copies the only slice field in a SonarQube user model.
func cloneUser(user sonar.User) sonar.User {
	user.Groups = append([]string(nil), user.Groups...)
	return user
}

// normalizeEmail returns a trimmed, case-insensitive email lookup key.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// normalizeName returns a trimmed, case-insensitive display-name lookup key.
func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
