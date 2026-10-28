// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package reconcile

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/woozymasta/guassp/internal/discovery"
	"github.com/woozymasta/guassp/internal/domain"
	"github.com/woozymasta/guassp/internal/gitlab"
	"github.com/woozymasta/guassp/internal/sonar"
)

type fakeReconcileGitLab struct {
	project      gitlab.Project
	projectErr   error
	members      []gitlab.Member
	membersErr   error
	projectCalls int
	memberCalls  int
}

func (client *fakeReconcileGitLab) Project(
	_ context.Context,
	reference string,
) (gitlab.Project, error) {
	client.projectCalls++
	if client.projectErr != nil {
		return gitlab.Project{}, client.projectErr
	}
	if reference != "42" {
		return gitlab.Project{}, errors.New("unexpected project reference")
	}

	return client.project, nil
}

func (client *fakeReconcileGitLab) ProjectMembers(
	_ context.Context,
	projectID int64,
) ([]gitlab.Member, error) {
	client.memberCalls++
	if projectID != 42 {
		return nil, errors.New("unexpected GitLab project ID")
	}
	if client.membersErr != nil {
		return nil, client.membersErr
	}

	return append([]gitlab.Member(nil), client.members...), nil
}

type fakeReconcileDiscovery struct {
	targets       []discovery.Project
	verifyResults map[string]bool
	verifyErrors  map[string]error
	lookupErr     error
	fallback      discovery.Project
	fallbackFound bool
	fallbackErr   error
	lookupCalls   int
	fallbackCalls int
	verifyCalls   []string
}

func (source *fakeReconcileDiscovery) Lookup(
	_ context.Context,
	projectID int64,
) ([]discovery.Project, error) {
	source.lookupCalls++
	if projectID != 42 {
		return nil, errors.New("unexpected GitLab project ID")
	}
	if source.lookupErr != nil {
		return nil, source.lookupErr
	}

	return append([]discovery.Project(nil), source.targets...), nil
}

func (source *fakeReconcileDiscovery) LegacyPathFallback(
	_ context.Context,
	path string,
) (discovery.Project, bool, error) {
	source.fallbackCalls++
	if path != "group/project" {
		return discovery.Project{}, false, errors.New("unexpected GitLab project path")
	}

	return source.fallback, source.fallbackFound, source.fallbackErr
}

func (source *fakeReconcileDiscovery) VerifyBinding(
	_ context.Context,
	projectID int64,
	projectKey string,
) (bool, error) {
	if projectID != 42 {
		return false, errors.New("unexpected GitLab project ID")
	}

	source.verifyCalls = append(source.verifyCalls, projectKey)
	if err := source.verifyErrors[projectKey]; err != nil {
		return false, err
	}
	if verified, exists := source.verifyResults[projectKey]; exists {
		return verified, nil
	}

	return true, nil
}

type reconcileWrite struct {
	action     string
	projectKey string
	login      string
	permission string
	value      string
}

type fakeReconcileSonar struct {
	permissions         map[string]map[string]domain.PermissionSet
	visibility          map[string]string
	currentVisibility   map[string]string
	visibilityReadError map[string]error
	readErrors          map[string]error
	writeErrors         map[string]error
	writes              []reconcileWrite
	reads               []string
	visibilityReads     []string
}

func (client *fakeReconcileSonar) DirectUserPermissions(
	_ context.Context,
	projectKey string,
) ([]sonar.UserPermissions, error) {
	client.reads = append(client.reads, projectKey)
	if err := client.readErrors[projectKey]; err != nil {
		return nil, err
	}

	users := client.permissions[projectKey]
	logins := make([]string, 0, len(users))
	for login := range users {
		logins = append(logins, login)
	}
	slices.Sort(logins)
	records := make([]sonar.UserPermissions, 0, len(logins))
	for _, login := range logins {
		records = append(records, sonar.UserPermissions{
			Login:       login,
			Permissions: users[login].Sorted(),
		})
	}

	return records, nil
}

func (client *fakeReconcileSonar) GrantUserPermission(
	_ context.Context,
	login, permission, projectKey string,
) error {
	client.writes = append(client.writes, reconcileWrite{
		action: "grant", projectKey: projectKey, login: login, permission: permission,
	})
	if err := client.writeErrors["grant:"+projectKey+":"+login+":"+permission]; err != nil {
		return err
	}

	client.ensurePermissionSet(projectKey, login)[permission] = struct{}{}
	return nil
}

func (client *fakeReconcileSonar) RevokeUserPermission(
	_ context.Context,
	login, permission, projectKey string,
) error {
	client.writes = append(client.writes, reconcileWrite{
		action: "revoke", projectKey: projectKey, login: login, permission: permission,
	})
	if err := client.writeErrors["revoke:"+projectKey+":"+login+":"+permission]; err != nil {
		return err
	}

	delete(client.ensurePermissionSet(projectKey, login), permission)
	return nil
}

func (client *fakeReconcileSonar) ProjectVisibility(
	_ context.Context,
	projectKey string,
) (string, error) {
	client.visibilityReads = append(client.visibilityReads, projectKey)
	if err := client.visibilityReadError[projectKey]; err != nil {
		return "", err
	}
	if visibility, exists := client.currentVisibility[projectKey]; exists {
		return visibility, nil
	}

	return "public", nil
}

func (client *fakeReconcileSonar) UpdateProjectVisibility(
	_ context.Context,
	projectKey, visibility string,
) error {
	client.writes = append(client.writes, reconcileWrite{
		action: "visibility", projectKey: projectKey, value: visibility,
	})
	if err := client.writeErrors["visibility:"+projectKey]; err != nil {
		return err
	}

	client.visibility[projectKey] = visibility
	client.currentVisibility[projectKey] = visibility
	return nil
}

func (client *fakeReconcileSonar) DeactivateUser(_ context.Context, user sonar.User) error {
	client.writes = append(client.writes, reconcileWrite{action: "deactivate", login: user.Login})
	return client.writeErrors["deactivate:"+user.Login]
}

func (client *fakeReconcileSonar) ensurePermissionSet(projectKey, login string) domain.PermissionSet {
	if client.permissions[projectKey] == nil {
		client.permissions[projectKey] = make(map[string]domain.PermissionSet)
	}
	if client.permissions[projectKey][login] == nil {
		client.permissions[projectKey][login] = make(domain.PermissionSet)
	}

	return client.permissions[projectKey][login]
}

func TestReconcilerGrantsAndIsIdempotent(t *testing.T) {
	users := []sonar.User{{
		Login:            "alice",
		ExternalProvider: "gitlab",
		ExternalIdentity: "alice",
		Active:           true,
	}}
	sonarClient := newFakeReconcileSonar()
	reconciler := newTestReconciler(t, users, []gitlab.Member{{
		ID:          7,
		Username:    "alice",
		State:       "active",
		AccessLevel: 30,
	}}, []discovery.Project{{
		Key:        "team:project",
		Visibility: "public",
	}},
		sonarClient, Options{
			Visibility: domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
		})

	first := reconciler.Reconcile(context.Background(), 42)
	if first.Status != StatusSuccess || first.Counts.Grants != 3 || first.Counts.Revokes != 0 {
		t.Fatalf("first result = %+v", first)
	}

	firstWriteCount := len(sonarClient.writes)
	second := reconciler.Reconcile(context.Background(), 42)
	if second.Status != StatusSuccess || second.Counts.Grants != 0 || second.Counts.Revokes != 0 {
		t.Fatalf("second result = %+v", second)
	}
	if len(sonarClient.writes) != firstWriteCount {
		t.Fatalf("writes after second run = %+v, want no new writes", sonarClient.writes)
	}
}

func TestReconcilerAppliesPermissionUpgradesAndDowngrades(t *testing.T) {
	tests := []struct {
		name        string
		level       int
		current     []string
		wantGrants  []string
		wantRevokes []string
	}{
		{
			name:    "upgrade",
			level:   40,
			current: []string{"user"},
			wantGrants: []string{
				"alice:codeviewer", "alice:issueadmin", "alice:securityhotspotadmin",
			},
			wantRevokes: nil,
		},
		{
			name:        "downgrade",
			level:       20,
			current:     []string{"user", "codeviewer", "issueadmin"},
			wantGrants:  nil,
			wantRevokes: []string{"alice:issueadmin"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sonarClient := newFakeReconcileSonar()
			sonarClient.permissions["team:project"] = map[string]domain.PermissionSet{
				"alice": domain.NewPermissionSet(test.current...),
			}
			reconciler := newTestReconciler(t, []sonar.User{{
				Login:            "alice",
				ExternalProvider: "gitlab",
				ExternalIdentity: "alice",
				Active:           true,
			}}, []gitlab.Member{{
				ID:          7,
				Username:    "alice",
				State:       "active",
				AccessLevel: test.level,
			}}, []discovery.Project{{Key: "team:project"}}, sonarClient, Options{
				Visibility: domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
			})

			result := reconciler.Reconcile(context.Background(), 42)
			if result.Status != StatusSuccess {
				t.Fatalf("result = %+v", result)
			}
			if got := writesOf(sonarClient.writes, "grant"); !slices.Equal(got, test.wantGrants) {
				t.Errorf("grants = %v, want %v", got, test.wantGrants)
			}
			if got := writesOf(sonarClient.writes, "revoke"); !slices.Equal(got, test.wantRevokes) {
				t.Errorf("revokes = %v, want %v", got, test.wantRevokes)
			}
		})
	}
}

func TestReconcilerProtectsUsersWithUnmappedAccessLevels(t *testing.T) {
	sonarClient := newFakeReconcileSonar()
	sonarClient.permissions["team:project"] = map[string]domain.PermissionSet{
		"alice": domain.NewPermissionSet("admin"),
	}
	reconciler := newTestReconciler(t, []sonar.User{{
		Login:            "alice",
		ExternalProvider: "gitlab",
		ExternalIdentity: "alice",
		Active:           true,
	}}, []gitlab.Member{{
		ID:          7,
		Username:    "alice",
		State:       "active",
		AccessLevel: 40,
	}}, []discovery.Project{{Key: "team:project"}}, sonarClient, Options{
		PermissionMap: domain.PermissionMap{
			10: domain.NewPermissionSet("user"),
			50: domain.NewPermissionSet("admin"),
		},
		Visibility: domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
	})

	result := reconciler.Reconcile(context.Background(), 42)
	if result.Status != StatusPartial || result.Counts.MappingMisses != 1 || len(result.Warnings) == 0 {
		t.Fatalf("result = %+v", result)
	}
	if len(sonarClient.writes) != 0 {
		t.Fatalf("unmapped member caused permission writes: %+v", sonarClient.writes)
	}
	if !sonarClient.permissions["team:project"]["alice"].Has("admin") {
		t.Fatal("unmapped member lost an existing permission")
	}
}

func TestReconcilerAppliesExplicitEmptyPermissionMapping(t *testing.T) {
	sonarClient := newFakeReconcileSonar()
	sonarClient.permissions["team:project"] = map[string]domain.PermissionSet{
		"alice": domain.NewPermissionSet("user"),
	}
	reconciler := newTestReconciler(t, []sonar.User{{
		Login:            "alice",
		ExternalProvider: "gitlab",
		ExternalIdentity: "alice",
		Active:           true,
	}}, []gitlab.Member{{
		ID:          7,
		Username:    "alice",
		State:       "active",
		AccessLevel: 25,
	}}, []discovery.Project{{Key: "team:project"}}, sonarClient, Options{
		PermissionMap: domain.PermissionMap{
			10: domain.NewPermissionSet("user"),
			25: domain.NewPermissionSet(),
		},
		Visibility: domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
	})

	result := reconciler.Reconcile(context.Background(), 42)
	if result.Status != StatusSuccess || result.Counts.MappingMisses != 0 || result.Counts.Revokes != 1 {
		t.Fatalf("result = %+v", result)
	}
	if got := writesOf(sonarClient.writes, "revoke"); !slices.Equal(got, []string{"alice:user"}) {
		t.Fatalf("revokes = %v", got)
	}
}

func TestReconcilerRevokesStaleManagedPermissionsSafely(t *testing.T) {
	users := []sonar.User{
		{Login: "alice", ExternalProvider: "gitlab", ExternalIdentity: "alice", Active: true},
		{Login: "former", ExternalProvider: "gitlab", ExternalIdentity: "former", Active: true},
		{Login: "local", ExternalProvider: "sonarqube", ExternalIdentity: "local", Active: true},
		{Login: "foreign", ExternalProvider: "ldap", ExternalIdentity: "foreign", Active: true},
		{
			Login:            "managed-elsewhere",
			ExternalProvider: "gitlab",
			ExternalIdentity: "elsewhere",
			Groups:           []string{"manual"},
			Active:           true,
		},
	}
	sonarClient := newFakeReconcileSonar()
	sonarClient.permissions["team:project"] = map[string]domain.PermissionSet{
		"alice":             domain.NewPermissionSet("user", "codeviewer", "scan"),
		"former":            domain.NewPermissionSet("user"),
		"local":             domain.NewPermissionSet("user"),
		"foreign":           domain.NewPermissionSet("user"),
		"managed-elsewhere": domain.NewPermissionSet("user"),
	}
	reconciler := newTestReconciler(t, users, []gitlab.Member{{
		ID:          7,
		Username:    "alice",
		State:       "active",
		AccessLevel: 10,
	}}, []discovery.Project{{Key: "team:project"}}, sonarClient, Options{
		Visibility: domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
	})
	reconciler.matcher.skipGroups["manual"] = struct{}{}

	result := reconciler.Reconcile(context.Background(), 42)
	if result.Status != StatusSuccess || result.Counts.Revokes != 2 {
		t.Fatalf("result = %+v", result)
	}
	if got := writesOf(sonarClient.writes, "revoke"); !slices.Equal(got, []string{"alice:codeviewer", "former:user"}) {
		t.Fatalf("revokes = %v", got)
	}
	if !sonarClient.permissions["team:project"]["alice"].Has("scan") {
		t.Fatal("unmanaged scan permission was removed")
	}
	for _, login := range []string{"local", "foreign", "managed-elsewhere"} {
		if !sonarClient.permissions["team:project"][login].Has("user") {
			t.Errorf("permission for %q was removed", login)
		}
	}
}

func TestReconcilerDoesNotMutateAmbiguousIdentity(t *testing.T) {
	sonarClient := newFakeReconcileSonar()
	sonarClient.permissions["team:project"] = map[string]domain.PermissionSet{
		"alice-old": domain.NewPermissionSet("user"),
		"alice-new": domain.NewPermissionSet("user"),
	}
	reconciler := newTestReconciler(t, []sonar.User{
		{Login: "alice-old", ExternalProvider: "gitlab", ExternalIdentity: "alice", Active: true},
		{Login: "alice-new", ExternalProvider: "gitlab", ExternalIdentity: "7", Active: true},
	}, []gitlab.Member{{
		ID:          7,
		Username:    "alice",
		State:       "active",
		AccessLevel: 40,
	}}, []discovery.Project{{Key: "team:project"}}, sonarClient, Options{
		Visibility: domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
	})

	result := reconciler.Reconcile(context.Background(), 42)
	if result.Status != StatusPartial || result.Counts.Ambiguous != 1 || len(sonarClient.writes) != 0 {
		t.Fatalf("result = %+v, writes = %+v", result, sonarClient.writes)
	}
}

func TestReconcilerSkipsReboundSonarProject(t *testing.T) {
	sonarClient := newFakeReconcileSonar()
	discoveryClient := &fakeReconcileDiscovery{
		targets:       []discovery.Project{{Key: "team:project"}},
		verifyResults: map[string]bool{"team:project": false},
	}
	reconciler := newTestReconcilerWithClients(
		t,
		&fakeReconcileGitLab{
			project: testGitLabProject(),
			members: []gitlab.Member{{ID: 7, Username: "alice", State: "active", AccessLevel: 10}},
		},
		[]sonar.User{{Login: "alice", ExternalProvider: "gitlab", ExternalIdentity: "alice", Active: true}},
		discoveryClient,
		sonarClient,
		Options{Visibility: domain.VisibilityPolicy{Mode: domain.VisibilityIgnore}},
	)

	result := reconciler.Reconcile(context.Background(), 42)
	if result.Status != StatusPartial || len(result.Warnings) == 0 || len(discoveryClient.verifyCalls) != 1 {
		t.Fatalf("result = %+v; verification calls = %v", result, discoveryClient.verifyCalls)
	}
	if len(sonarClient.reads) != 0 || len(sonarClient.writes) != 0 {
		t.Fatalf("rebound target was reconciled: reads=%v writes=%+v", sonarClient.reads, sonarClient.writes)
	}
}

func TestReconcilerRechecksStaleBindingHintBeforeWrites(t *testing.T) {
	sonarClient := newFakeReconcileSonar()
	discoveryClient := &fakeReconcileDiscovery{
		targets: []discovery.Project{{Key: "team:project", BindingStale: true}},
	}
	reconciler := newTestReconcilerWithClients(
		t,
		&fakeReconcileGitLab{
			project: testGitLabProject(),
			members: []gitlab.Member{{ID: 7, Username: "alice", State: "active", AccessLevel: 10}},
		},
		[]sonar.User{{Login: "alice", ExternalProvider: "gitlab", ExternalIdentity: "alice", Active: true}},
		discoveryClient,
		sonarClient,
		Options{Visibility: domain.VisibilityPolicy{Mode: domain.VisibilityIgnore}},
	)

	result := reconciler.Reconcile(context.Background(), 42)
	if result.Status != StatusPartial || result.Counts.Grants != 1 || len(discoveryClient.verifyCalls) != 1 {
		t.Fatalf("result = %+v; verification calls = %v", result, discoveryClient.verifyCalls)
	}
	if !slices.Contains(writesOf(sonarClient.writes, "grant"), "alice:user") {
		t.Fatalf("verified stale hint was not reconciled: %+v", sonarClient.writes)
	}
}

func TestReconcilerContinuesWhenOneBindingCannotBeVerified(t *testing.T) {
	sonarClient := newFakeReconcileSonar()
	discoveryClient := &fakeReconcileDiscovery{
		targets:      []discovery.Project{{Key: "working"}, {Key: "broken"}},
		verifyErrors: map[string]error{"broken": errors.New("binding unavailable")},
	}
	reconciler := newTestReconcilerWithClients(
		t,
		&fakeReconcileGitLab{
			project: testGitLabProject(),
			members: []gitlab.Member{{ID: 7, Username: "alice", State: "active", AccessLevel: 10}},
		},
		[]sonar.User{{Login: "alice", ExternalProvider: "gitlab", ExternalIdentity: "alice", Active: true}},
		discoveryClient,
		sonarClient,
		Options{Visibility: domain.VisibilityPolicy{Mode: domain.VisibilityIgnore}},
	)

	result := reconciler.Reconcile(context.Background(), 42)
	if result.Status != StatusPartial || result.Counts.Grants != 1 || result.Counts.Errors != 1 {
		t.Fatalf("result = %+v", result)
	}
	if !slices.Contains(sonarClient.reads, "working") || slices.Contains(sonarClient.reads, "broken") {
		t.Fatalf("Sonar reads = %v; expected only verified target", sonarClient.reads)
	}
}

func TestReconcilerHandlesInactiveMembersAndDeactivation(t *testing.T) {
	for _, test := range []struct {
		name              string
		deactivate        bool
		wantDeactivations int
	}{
		{name: "deactivation disabled"},
		{name: "deactivation enabled", deactivate: true, wantDeactivations: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			sonarClient := newFakeReconcileSonar()
			sonarClient.ensurePermissionSet("team:project", "alice")["user"] = struct{}{}
			reconciler := newTestReconciler(t, []sonar.User{{
				Login:            "alice",
				ExternalProvider: "gitlab",
				ExternalIdentity: "alice",
				Active:           true,
			}}, []gitlab.Member{{
				ID:          7,
				Username:    "alice",
				State:       "blocked",
				AccessLevel: 40,
			}}, []discovery.Project{{Key: "team:project"}}, sonarClient, Options{
				Visibility:           domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
				SyncUserDeactivation: test.deactivate,
			})

			result := reconciler.Reconcile(context.Background(), 42)
			if result.Status != StatusSuccess || result.Counts.Revokes != 1 ||
				result.Counts.Deactivations != test.wantDeactivations {
				t.Fatalf("result = %+v", result)
			}
			if got := len(writesOf(sonarClient.writes, "grant")); got != 0 {
				t.Fatalf("grants = %d, want 0", got)
			}
		})
	}
}

func TestReconcilerDoesNotDeactivateActiveGitLabMember(t *testing.T) {
	sonarClient := newFakeReconcileSonar()
	sonarClient.permissions["team:project"] = map[string]domain.PermissionSet{
		"alice": domain.NewPermissionSet("user"),
	}
	reconciler := newTestReconciler(t, []sonar.User{{
		Login:            "alice",
		ExternalProvider: "gitlab",
		ExternalIdentity: "alice",
		Active:           true,
	}}, []gitlab.Member{{
		ID:          7,
		Username:    "alice",
		State:       "active",
		AccessLevel: 10,
	}}, []discovery.Project{{Key: "team:project"}}, sonarClient, Options{
		Visibility:           domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
		SyncUserDeactivation: true,
	})

	result := reconciler.Reconcile(context.Background(), 42)
	if result.Status != StatusSuccess || result.Counts.Deactivations != 0 || len(sonarClient.writes) != 0 {
		t.Fatalf("result = %+v; writes = %+v", result, sonarClient.writes)
	}
}

func TestReconcilerProtectsUnknownGitLabMemberState(t *testing.T) {
	for _, state := range []string{"", "future_state"} {
		t.Run(state, func(t *testing.T) {
			sonarClient := newFakeReconcileSonar()
			sonarClient.permissions["team:project"] = map[string]domain.PermissionSet{
				"alice": domain.NewPermissionSet("user"),
			}
			reconciler := newTestReconciler(t, []sonar.User{{
				Login:            "alice",
				ExternalProvider: "gitlab",
				ExternalIdentity: "alice",
				Active:           true,
			}}, []gitlab.Member{{
				ID:          7,
				Username:    "alice",
				State:       state,
				AccessLevel: 40,
			}}, []discovery.Project{{Key: "team:project"}}, sonarClient, Options{
				Visibility:           domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
				SyncUserDeactivation: true,
			})

			result := reconciler.Reconcile(context.Background(), 42)
			if result.Status != StatusPartial || result.Counts.UnknownUserStates != 1 || len(result.Warnings) == 0 {
				t.Fatalf("result = %+v", result)
			}
			if len(sonarClient.writes) != 0 {
				t.Fatalf("unknown state caused writes: %+v", sonarClient.writes)
			}
		})
	}
}

func TestReconcilerDoesNotGloballyDeactivateRemovedProjectMember(t *testing.T) {
	sonarClient := newFakeReconcileSonar()
	sonarClient.permissions["team:project"] = map[string]domain.PermissionSet{
		"alice": domain.NewPermissionSet("user"),
	}
	reconciler := newTestReconciler(t, []sonar.User{{
		Login:            "alice",
		ExternalProvider: "gitlab",
		ExternalIdentity: "alice",
		Active:           true,
	}}, nil, []discovery.Project{{Key: "team:project"}}, sonarClient, Options{
		Visibility:           domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
		SyncUserDeactivation: true,
	})

	result := reconciler.Reconcile(context.Background(), 42)
	if result.Status != StatusSuccess || result.Counts.Revokes != 1 || result.Counts.Deactivations != 0 {
		t.Fatalf("result = %+v", result)
	}
	if got := writesOf(sonarClient.writes, "deactivate"); len(got) != 0 {
		t.Fatalf("global deactivations = %v, want none", got)
	}
}

func TestReconcilerContinuesAcrossTargetsAndReusesGitLabReads(t *testing.T) {
	gitlabClient := &fakeReconcileGitLab{
		project: testGitLabProject(),
		members: []gitlab.Member{{ID: 7, Username: "alice", State: "active", AccessLevel: 10}},
	}
	sonarClient := newFakeReconcileSonar()
	sonarClient.readErrors["broken"] = errors.New("upstream token=hidden")
	discoveryClient := &fakeReconcileDiscovery{targets: []discovery.Project{
		{Key: "working"}, {Key: "broken"},
	}}
	reconciler := newTestReconcilerWithClients(t, gitlabClient, []sonar.User{{
		Login:            "alice",
		ExternalProvider: "gitlab",
		ExternalIdentity: "alice",
		Active:           true,
	}}, discoveryClient, sonarClient, Options{
		Visibility: domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
	})

	result := reconciler.Reconcile(context.Background(), 42)
	if result.Status != StatusPartial || result.Counts.Grants != 1 || result.Counts.Errors != 1 {
		t.Fatalf("result = %+v", result)
	}
	if gitlabClient.projectCalls != 1 || gitlabClient.memberCalls != 1 {
		t.Fatalf("GitLab calls = project %d, members %d", gitlabClient.projectCalls, gitlabClient.memberCalls)
	}
	if !slices.Contains(sonarClient.reads, "working") || !slices.Contains(sonarClient.reads, "broken") {
		t.Fatalf("target reads = %v", sonarClient.reads)
	}
	if strings.Contains(strings.Join(result.Errors, " "), "hidden") {
		t.Fatalf("error details leaked: %v", result.Errors)
	}
}

func TestReconcilerProcessesEveryBoundTarget(t *testing.T) {
	sonarClient := newFakeReconcileSonar()
	reconciler := newTestReconciler(t, []sonar.User{{
		Login:            "alice",
		ExternalProvider: "gitlab",
		ExternalIdentity: "alice",
		Active:           true,
	}}, []gitlab.Member{{
		ID:          7,
		Username:    "alice",
		State:       "active",
		AccessLevel: 10,
	}}, []discovery.Project{{Key: "first"}, {Key: "second"}}, sonarClient, Options{
		Visibility: domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
	})

	result := reconciler.Reconcile(context.Background(), 42)
	if result.Status != StatusSuccess || result.Counts.Targets != 2 || result.Counts.Grants != 2 {
		t.Fatalf("result = %+v", result)
	}
	if !slices.Equal(sonarClient.reads, []string{"first", "second"}) {
		t.Fatalf("target reads = %v", sonarClient.reads)
	}
	if got := writesOf(sonarClient.writes, "grant"); !slices.Equal(got, []string{"alice:user", "alice:user"}) {
		t.Fatalf("grants = %v", got)
	}
}

func TestReconcilerVisibilityFailureDoesNotBlockPermissions(t *testing.T) {
	sonarClient := newFakeReconcileSonar()
	sonarClient.currentVisibility["team:project"] = "private"
	sonarClient.writeErrors["visibility:team:project"] = errors.New("visibility rejected")
	reconciler := newTestReconciler(t, []sonar.User{{
		Login:            "alice",
		ExternalProvider: "gitlab",
		ExternalIdentity: "alice",
		Active:           true,
	}}, []gitlab.Member{{
		ID:          7,
		Username:    "alice",
		State:       "active",
		AccessLevel: 10,
	}}, []discovery.Project{{Key: "team:project", Visibility: "private"}}, sonarClient, Options{})

	result := reconciler.Reconcile(context.Background(), 42)
	if result.Status != StatusPartial || result.Counts.Grants != 1 || result.Counts.Errors != 1 {
		t.Fatalf("result = %+v", result)
	}
	if !slices.Contains(writesOf(sonarClient.writes, "grant"), "alice:user") {
		t.Fatalf("permission grant was blocked: %+v", sonarClient.writes)
	}
}

func TestPermissionReadFailureIsNotMaskedByIgnoredVisibility(t *testing.T) {
	sonarClient := newFakeReconcileSonar()
	sonarClient.readErrors["team:project"] = errors.New("permission endpoint unavailable")
	reconciler := newTestReconciler(t, nil, nil, []discovery.Project{{Key: "team:project"}}, sonarClient, Options{
		Visibility: domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
	})

	result := reconciler.Reconcile(context.Background(), 42)
	if result.Status != StatusFailed || result.Counts.Errors != 1 {
		t.Fatalf("result = %+v; permission failure must fail the run", result)
	}
	if result.Stages.Permissions.Status != StageFailed ||
		result.Stages.Visibility.Status != StageSkipped {
		t.Fatalf("stages = %+v; want permissions failed and visibility skipped", result.Stages)
	}
}

func TestReconcilerAggregatesIndependentTargetStages(t *testing.T) {
	sonarClient := newFakeReconcileSonar()
	sonarClient.readErrors["broken"] = errors.New("permission endpoint unavailable")
	reconciler := newTestReconciler(t, nil, nil, []discovery.Project{
		{Key: "working"},
		{Key: "broken"},
	}, sonarClient, Options{
		Visibility: domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
	})

	result := reconciler.Reconcile(context.Background(), 42)
	if result.Status != StatusPartial || result.Counts.Errors != len(result.Errors) || result.Counts.Errors != 1 {
		t.Fatalf("result = %+v", result)
	}
	if stages := result.Stages.Permissions; stages.Status != StagePartial ||
		stages.Attempts != 2 || stages.Succeeded != 1 || stages.Failed != 1 {
		t.Fatalf("permission stages = %+v", stages)
	}
	if stages := result.Stages.Visibility; stages.Status != StageSkipped || stages.Skipped != 2 {
		t.Fatalf("visibility stages = %+v", stages)
	}
}

func TestReconcilerSkipsConfiguredGitLabUser(t *testing.T) {
	sonarClient := newFakeReconcileSonar()
	sonarClient.permissions["team:project"] = map[string]domain.PermissionSet{
		"alice": domain.NewPermissionSet("user"),
	}
	reconciler := newTestReconciler(t, []sonar.User{{
		Login:            "alice",
		ExternalProvider: "gitlab",
		ExternalIdentity: "alice",
		Active:           true,
	}}, []gitlab.Member{{
		ID:          7,
		Username:    "alice",
		State:       "active",
		AccessLevel: 40,
	}}, []discovery.Project{{Key: "team:project"}}, sonarClient, Options{
		SkipGitLabUsers: []int64{7},
		Visibility:      domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
	})

	result := reconciler.Reconcile(context.Background(), 42)
	if result.Status != StatusSuccess || result.Counts.SkippedUsers != 1 || len(sonarClient.writes) != 0 {
		t.Fatalf("result = %+v, writes = %+v", result, sonarClient.writes)
	}
}

func TestReconcilerRetriesFailedPermissionStage(t *testing.T) {
	sonarClient := newFakeReconcileSonar()
	sonarClient.writeErrors["grant:team:project:alice:user"] = errors.New("upstream token=hidden")
	reconciler := newTestReconciler(t, []sonar.User{{
		Login:            "alice",
		ExternalProvider: "gitlab",
		ExternalIdentity: "alice",
		Active:           true,
	}}, []gitlab.Member{{
		ID:          7,
		Username:    "alice",
		State:       "active",
		AccessLevel: 10,
	}}, []discovery.Project{{Key: "team:project"}}, sonarClient, Options{
		Visibility: domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
	})

	first := reconciler.Reconcile(context.Background(), 42)
	if first.Status != StatusFailed || first.Counts.Errors != 1 || first.Counts.Grants != 0 {
		t.Fatalf("first result = %+v", first)
	}
	if first.Stages.Permissions.Status != StageFailed {
		t.Fatalf("permission stage = %+v; want failed", first.Stages.Permissions)
	}
	if strings.Contains(strings.Join(first.Errors, " "), "hidden") {
		t.Fatalf("error details leaked: %v", first.Errors)
	}

	delete(sonarClient.writeErrors, "grant:team:project:alice:user")
	second := reconciler.Reconcile(context.Background(), 42)
	if second.Status != StatusSuccess || second.Counts.Grants != 1 || second.Counts.Errors != 0 {
		t.Fatalf("second result = %+v", second)
	}
}

func TestReconcilerReportsMixedPermissionWritesAsPartial(t *testing.T) {
	sonarClient := newFakeReconcileSonar()
	sonarClient.writeErrors["grant:team:project:alice:user"] = errors.New("permission rejected")
	reconciler := newTestReconciler(t, []sonar.User{{
		Login:            "alice",
		ExternalProvider: "gitlab",
		ExternalIdentity: "alice",
		Active:           true,
	}}, []gitlab.Member{{
		ID:          7,
		Username:    "alice",
		State:       "active",
		AccessLevel: 30,
	}}, []discovery.Project{{Key: "team:project"}}, sonarClient, Options{
		Visibility: domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
	})

	result := reconciler.Reconcile(context.Background(), 42)
	if result.Status != StatusPartial || result.Counts.Grants != 2 || result.Counts.Errors != 1 {
		t.Fatalf("result = %+v", result)
	}
	if stages := result.Stages.Permissions; stages.Status != StagePartial ||
		stages.Attempts != 1 || stages.Partial != 1 {
		t.Fatalf("permission stage = %+v", stages)
	}
}

func TestReconcilerUsesLiveVisibilityInsteadOfDiscoverySnapshot(t *testing.T) {
	for _, test := range []struct {
		name           string
		current        string
		snapshot       string
		wantVisibility string
		wantWriteCount int
	}{
		{name: "live value already matches", current: "private", snapshot: "public"},
		{
			name:           "live value needs update",
			current:        "public",
			snapshot:       "private",
			wantVisibility: "private",
			wantWriteCount: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sonarClient := newFakeReconcileSonar()
			sonarClient.currentVisibility["team:project"] = test.current
			gitLabClient := &fakeReconcileGitLab{project: gitlab.Project{
				ID:                42,
				PathWithNamespace: "group/project",
				Visibility:        "internal",
			}}
			reconciler := newTestReconcilerWithClients(
				t,
				gitLabClient,
				nil,
				&fakeReconcileDiscovery{targets: []discovery.Project{{
					Key: "team:project", Visibility: test.snapshot,
				}}},
				sonarClient,
				Options{},
			)

			result := reconciler.Reconcile(context.Background(), 42)
			if result.Status != StatusSuccess || len(writesOf(sonarClient.writes, "visibility")) != test.wantWriteCount {
				t.Fatalf("result = %+v; writes = %+v", result, sonarClient.writes)
			}
			if test.wantWriteCount != 0 && sonarClient.visibility["team:project"] != test.wantVisibility {
				t.Fatalf("visibility write = %q, want %q", sonarClient.visibility["team:project"], test.wantVisibility)
			}
			if len(sonarClient.visibilityReads) != 1 {
				t.Fatalf("visibility reads = %v, want one current-state read", sonarClient.visibilityReads)
			}
		})
	}
}

func TestReconcilerDoesNotReadVisibilityWhenDisabled(t *testing.T) {
	sonarClient := newFakeReconcileSonar()
	reconciler := newTestReconciler(t, nil, nil, []discovery.Project{{
		Key:        "team:project",
		Visibility: "private",
	}}, sonarClient, Options{
		Visibility: domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
	})

	result := reconciler.Reconcile(context.Background(), 42)
	if result.Status != StatusSuccess || len(sonarClient.visibilityReads) != 0 ||
		len(writesOf(sonarClient.writes, "visibility")) != 0 {
		t.Fatalf("result = %+v; reads = %v; writes = %+v", result, sonarClient.visibilityReads, sonarClient.writes)
	}
}

func TestReconcilerVisibilityReadFailureDoesNotBlockPermissions(t *testing.T) {
	sonarClient := newFakeReconcileSonar()
	sonarClient.visibilityReadError["team:project"] = errors.New("visibility unavailable")
	reconciler := newTestReconciler(t, []sonar.User{{
		Login:            "alice",
		ExternalProvider: "gitlab",
		ExternalIdentity: "alice",
		Active:           true,
	}}, []gitlab.Member{{
		ID:          7,
		Username:    "alice",
		State:       "active",
		AccessLevel: 10,
	}}, []discovery.Project{{Key: "team:project"}}, sonarClient, Options{})

	result := reconciler.Reconcile(context.Background(), 42)
	if result.Status != StatusPartial || result.Counts.Grants != 1 || result.Counts.Errors != 1 {
		t.Fatalf("result = %+v", result)
	}
	if !slices.Contains(writesOf(sonarClient.writes, "grant"), "alice:user") {
		t.Fatalf("permission grant was blocked: %+v", sonarClient.writes)
	}
}

func TestReconcilerLegacyFallback(t *testing.T) {
	t.Run("uses one fallback result", func(t *testing.T) {
		sonarClient := newFakeReconcileSonar()
		discoveryClient := &fakeReconcileDiscovery{
			fallback:      discovery.Project{Key: "legacy", Visibility: "public"},
			fallbackFound: true,
		}
		options := Options{
			DiscoveryMode: domain.ProjectDiscoveryBindingPathFallback,
			Visibility:    domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
		}
		reconciler := newTestReconcilerWithClients(
			t,
			&fakeReconcileGitLab{project: testGitLabProject()},
			nil,
			discoveryClient,
			sonarClient,
			options,
		)

		result := reconciler.Reconcile(context.Background(), 42)
		if result.Status != StatusSuccess || discoveryClient.fallbackCalls != 1 ||
			!slices.Contains(sonarClient.reads, "legacy") {
			t.Fatalf("result = %+v; fallback calls=%d reads=%v", result, discoveryClient.fallbackCalls, sonarClient.reads)
		}
	})

	t.Run("does not reconcile ambiguous fallback", func(t *testing.T) {
		sonarClient := newFakeReconcileSonar()
		discoveryClient := &fakeReconcileDiscovery{}
		reconciler := newTestReconcilerWithClients(
			t,
			&fakeReconcileGitLab{project: testGitLabProject()},
			nil,
			discoveryClient,
			sonarClient,
			Options{
				DiscoveryMode: domain.ProjectDiscoveryBindingPathFallback,
				Visibility:    domain.VisibilityPolicy{Mode: domain.VisibilityIgnore},
			},
		)

		result := reconciler.Reconcile(context.Background(), 42)
		if result.Status != StatusPartial || result.Counts.Targets != 0 || len(result.Warnings) == 0 ||
			discoveryClient.fallbackCalls != 1 || len(sonarClient.reads) != 0 || len(sonarClient.writes) != 0 {
			t.Fatalf("result = %+v; fallback calls = %d; reads = %v; writes = %+v",
				result, discoveryClient.fallbackCalls, sonarClient.reads, sonarClient.writes)
		}
	})
}

func newFakeReconcileSonar() *fakeReconcileSonar {
	return &fakeReconcileSonar{
		permissions:         make(map[string]map[string]domain.PermissionSet),
		visibility:          make(map[string]string),
		currentVisibility:   make(map[string]string),
		visibilityReadError: make(map[string]error),
		readErrors:          make(map[string]error),
		writeErrors:         make(map[string]error),
	}
}

func newTestReconciler(
	t *testing.T,
	users []sonar.User,
	members []gitlab.Member,
	targets []discovery.Project,
	sonarClient *fakeReconcileSonar,
	options Options,
) *Reconciler {
	t.Helper()
	gitlabClient := &fakeReconcileGitLab{project: testGitLabProject(), members: members}
	discoveryClient := &fakeReconcileDiscovery{targets: targets}
	return newTestReconcilerWithClients(t, gitlabClient, users, discoveryClient, sonarClient, options)
}

func newTestReconcilerWithClients(
	t *testing.T,
	gitlabClient *fakeReconcileGitLab,
	users []sonar.User,
	discoveryClient *fakeReconcileDiscovery,
	sonarClient *fakeReconcileSonar,
	options Options,
) *Reconciler {
	t.Helper()
	directory, err := NewUserDirectory(&fakeSonarUserSource{users: users})
	if err != nil {
		t.Fatalf("NewUserDirectory: %v", err)
	}
	matcher, err := NewUserMatcher(directory, domain.UserMatchExternal, []string{"manual"}, nil)
	if err != nil {
		t.Fatalf("NewUserMatcher: %v", err)
	}
	reconciler, err := NewReconciler(
		gitlabClient,
		sonarClient,
		discoveryClient,
		directory,
		matcher,
		options,
	)
	if err != nil {
		t.Fatalf("NewReconciler: %v", err)
	}

	return reconciler
}

func testGitLabProject() gitlab.Project {
	return gitlab.Project{ID: 42, PathWithNamespace: "group/project", Visibility: "public"}
}

func writesOf(writes []reconcileWrite, action string) []string {
	var values []string
	for _, write := range writes {
		if write.action != action {
			continue
		}
		if action == "visibility" || action == "deactivate" {
			values = append(values, write.value)
			continue
		}
		values = append(values, write.login+":"+write.permission)
	}
	slices.Sort(values)

	return values
}
