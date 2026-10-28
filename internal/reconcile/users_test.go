// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package reconcile

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/woozymasta/guassp/internal/domain"
	"github.com/woozymasta/guassp/internal/gitlab"
	"github.com/woozymasta/guassp/internal/sonar"
)

type fakeSonarUserSource struct {
	mu      sync.Mutex
	users   []sonar.User
	load    func(int) []sonar.User
	calls   int
	entered chan struct{}
	release chan struct{}
}

func (source *fakeSonarUserSource) Users(ctx context.Context) ([]sonar.User, error) {
	source.mu.Lock()
	source.calls++
	calls := source.calls
	users := cloneUsers(source.users)
	load := source.load
	entered := source.entered
	release := source.release
	source.mu.Unlock()

	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}

	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if load != nil {
		return load(calls), nil
	}

	return users, nil
}

func (source *fakeSonarUserSource) callCount() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.calls
}

type fakeGitLabUserLookup struct {
	user  gitlab.User
	err   error
	calls int
}

func (lookup *fakeGitLabUserLookup) User(_ context.Context, userID int64) (gitlab.User, error) {
	lookup.calls++
	if lookup.user.ID != 0 && lookup.user.ID != userID {
		return gitlab.User{}, errors.New("unexpected GitLab user ID")
	}

	return lookup.user, lookup.err
}

func TestUserDirectoryCachesExpiresAndProtectsSnapshots(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	source := &fakeSonarUserSource{users: []sonar.User{{Login: "alice", Groups: []string{"developers"}}}}
	directory := testUserDirectory(source, &now)

	users, err := directory.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	users[0].Groups[0] = "changed"
	if _, err := directory.Snapshot(context.Background()); err != nil {
		t.Fatalf("cached Snapshot: %v", err)
	}
	user, found, err := directory.Lookup(context.Background(), "alice")
	if err != nil || !found || !slices.Equal(user.Groups, []string{"developers"}) {
		t.Fatalf("Lookup = %+v, %t, %v", user, found, err)
	}
	if got := source.callCount(); got != 1 {
		t.Fatalf("source calls before expiry = %d, want 1", got)
	}

	now = now.Add(userDirectoryTTL)
	if _, err := directory.Snapshot(context.Background()); err != nil {
		t.Fatalf("expired Snapshot: %v", err)
	}
	if got := source.callCount(); got != 2 {
		t.Fatalf("source calls after expiry = %d, want 2", got)
	}
}

func TestUserDirectorySerializesConcurrentRefreshes(t *testing.T) {
	source := &fakeSonarUserSource{
		users:   []sonar.User{{Login: "alice"}},
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	directory := testUserDirectory(source, nil)
	const readers = 8
	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(readers)
	for range readers {
		go func() {
			defer wait.Done()
			<-start
			if _, err := directory.Snapshot(context.Background()); err != nil {
				t.Errorf("Snapshot: %v", err)
			}
		}()
	}
	close(start)
	<-source.entered
	close(source.release)
	wait.Wait()

	if got := source.callCount(); got != 1 {
		t.Fatalf("concurrent source calls = %d, want 1", got)
	}
}

func TestUserMatcherExternalIdentityAndProvider(t *testing.T) {
	tests := []struct {
		name  string
		users []sonar.User
		want  MatchStatus
	}{
		{
			name: "username",
			users: []sonar.User{{
				Login: "alice", ExternalProvider: "gitlab", ExternalIdentity: "alice",
			}},
			want: MatchMatched,
		},
		{
			name: "numeric ID",
			users: []sonar.User{{
				Login: "alice", ExternalProvider: "gitlab", ExternalIdentity: "7",
			}},
			want: MatchMatched,
		},
		{
			name: "provider mismatch",
			users: []sonar.User{{
				Login: "alice", ExternalProvider: "ldap", ExternalIdentity: "alice",
			}},
			want: MatchUnmatched,
		},
		{
			name: "ambiguous identities",
			users: []sonar.User{
				{Login: "alice", ExternalProvider: "gitlab", ExternalIdentity: "alice"},
				{Login: "alice-old", ExternalProvider: "gitlab", ExternalIdentity: "7"},
			},
			want: MatchAmbiguous,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matcher := testUserMatcher(t, test.users, domain.UserMatchExternal, nil, nil)
			result, err := matcher.Match(context.Background(), gitlab.Member{ID: 7, Username: "alice"})
			if err != nil || result.Status != test.want {
				t.Fatalf("Match = %+v, %v; want %q", result, err, test.want)
			}
		})
	}
}

func TestUserMatcherDeduplicatesLoginAndAppliesSkipGroups(t *testing.T) {
	users := []sonar.User{
		{Login: "alice", ExternalProvider: "gitlab", ExternalIdentity: "alice", Groups: []string{"developers"}},
		{Login: "alice", ExternalProvider: "gitlab", ExternalIdentity: "7", Groups: []string{"managed-elsewhere"}},
	}
	matcher := testUserMatcher(t, users, domain.UserMatchExternal, []string{"managed-elsewhere"}, nil)
	result, err := matcher.Match(context.Background(), gitlab.Member{ID: 7, Username: "alice"})
	if err != nil || result.Status != MatchSkipped || result.User.Login != "alice" {
		t.Fatalf("Match = %+v, %v", result, err)
	}
}

func TestUserMatcherLegacyEmailRequiresVerifiedIdentity(t *testing.T) {
	users := []sonar.User{
		{
			Login: "alice", Email: "Alice@Example.com", ExternalProvider: "gitlab", ExternalIdentity: "alice",
		},
		{
			Login: "ldap-alice", Email: "alice@example.com", ExternalProvider: "ldap", ExternalIdentity: "alice",
		},
		{
			Login: "other-alice", Email: "alice@example.com", ExternalProvider: "gitlab", ExternalIdentity: "someone-else",
		},
	}
	lookup := &fakeGitLabUserLookup{user: gitlab.User{ID: 7, Email: " alice@example.com "}}
	matcher := testUserMatcher(t, users, domain.UserMatchEmail, nil, lookup)
	result, err := matcher.Match(context.Background(), gitlab.Member{ID: 7, Username: "alice"})
	if err != nil || result.Status != MatchMatched || result.User.Login != "alice" {
		t.Fatalf("Match = %+v, %v", result, err)
	}
	if lookup.calls != 1 {
		t.Fatalf("GitLab user lookups = %d, want 1", lookup.calls)
	}
}

func TestUserMatcherLegacyNameRequiresVerifiedIdentity(t *testing.T) {
	tests := []struct {
		name string
		user sonar.User
		want MatchStatus
	}{
		{
			name: "matching GitLab identity",
			user: sonar.User{Login: "alice", Name: "Alice Example", ExternalProvider: "gitlab", ExternalIdentity: "7"},
			want: MatchMatched,
		},
		{
			name: "foreign provider",
			user: sonar.User{Login: "alice", Name: "Alice Example", ExternalProvider: "ldap", ExternalIdentity: "7"},
			want: MatchUnmatched,
		},
		{
			name: "different identity",
			user: sonar.User{Login: "alice", Name: "Alice Example", ExternalProvider: "gitlab", ExternalIdentity: "other"},
			want: MatchUnmatched,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matcher := testUserMatcher(t, []sonar.User{test.user}, domain.UserMatchName, nil, nil)
			result, err := matcher.Match(
				context.Background(), gitlab.Member{ID: 7, Username: "alice", Name: " Alice Example "},
			)
			if err != nil || result.Status != test.want {
				t.Fatalf("Match = %+v, %v; want %q", result, err, test.want)
			}
		})
	}
}

func TestUserMatcherRefreshesOnceOnMiss(t *testing.T) {
	source := &fakeSonarUserSource{load: func(call int) []sonar.User {
		if call == 1 {
			return nil
		}
		return []sonar.User{{Login: "alice", ExternalProvider: "gitlab", ExternalIdentity: "alice"}}
	}}
	directory := testUserDirectory(source, nil)
	matcher, err := NewUserMatcher(directory, domain.UserMatchExternal, nil, nil)
	if err != nil {
		t.Fatalf("NewUserMatcher: %v", err)
	}

	result, err := matcher.Match(context.Background(), gitlab.Member{ID: 7, Username: "alice"})
	if err != nil || result.Status != MatchMatched || result.User.Login != "alice" {
		t.Fatalf("Match = %+v, %v", result, err)
	}
	if got := source.callCount(); got != 2 {
		t.Fatalf("source calls = %d, want 2", got)
	}
}

func testUserDirectory(source SonarUserSource, now *time.Time) *UserDirectory {
	directory, err := NewUserDirectory(source)
	if err != nil {
		panic(err)
	}
	if now != nil {
		directory.now = func() time.Time { return *now }
	}

	return directory
}

func testUserMatcher(
	t *testing.T,
	users []sonar.User,
	mode domain.UserMatchMode,
	skipGroups []string,
	gitlabUsers GitLabUserLookup,
) *UserMatcher {
	t.Helper()
	directory := testUserDirectory(&fakeSonarUserSource{users: users}, nil)
	matcher, err := NewUserMatcher(directory, mode, skipGroups, gitlabUsers)
	if err != nil {
		t.Fatalf("NewUserMatcher: %v", err)
	}

	return matcher
}
