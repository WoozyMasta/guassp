// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package web_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/woozymasta/guassp/internal/discovery"
	"github.com/woozymasta/guassp/internal/domain"
	"github.com/woozymasta/guassp/internal/gitlab"
	"github.com/woozymasta/guassp/internal/observability"
	"github.com/woozymasta/guassp/internal/rate"
	"github.com/woozymasta/guassp/internal/reconcile"
	"github.com/woozymasta/guassp/internal/scheduler"
	"github.com/woozymasta/guassp/internal/sonar"
	"github.com/woozymasta/guassp/internal/web"
)

func TestRealClientsReconcileThroughCISyncAndRemainIdempotent(t *testing.T) {
	var sonarState struct {
		sync.Mutex
		permissions map[string]map[string]map[string]bool
		visibility  string
		writes      []string
	}
	sonarState.permissions = map[string]map[string]map[string]bool{
		"sonar:project": {
			"alice": {"user": true, "admin": true, "scan": true},
			"bob":   {"user": true},
		},
	}
	sonarState.visibility = "private"

	gitLabServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/gitlab/api/v4/job":
			if request.Header.Get("JOB-TOKEN") != "ci-token" {
				http.Error(writer, "invalid token", http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(writer, `{"id":55,"project":{"id":123}}`)

		case "/gitlab/api/v4/projects/123":
			_, _ = io.WriteString(writer, `{"id":123,"name":"Project","path_with_namespace":"group/project",`+
				`"web_url":"https://gitlab.example.com/group/project","visibility":"public"}`)

		case "/gitlab/api/v4/projects/123/members/all":
			_, _ = io.WriteString(writer, `[{"id":1,"username":"alice","name":"Alice",`+
				`"state":"active","access_level":30}]`)

		default:
			http.NotFound(writer, request)
		}
	}))
	defer gitLabServer.Close()

	sonarServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/sonar/api/server/version":
			_, _ = io.WriteString(writer, "10.3.0")

		case "/sonar/api/projects/search":
			_, _ = io.WriteString(writer, `{"components":[{"key":"sonar:project","name":"Project",`+
				`"visibility":"private"}],"paging":{"pageIndex":1,"pageSize":100,"total":1}}`)

		case "/sonar/api/alm_settings/get_binding":
			_, _ = io.WriteString(writer, `{"key":"GitLab","alm":"gitlab","repository":"123"}`)

		case "/sonar/api/permissions/users":
			sonarState.Lock()
			entries := make([]map[string]any, 0, len(sonarState.permissions["sonar:project"]))
			for login, permissions := range sonarState.permissions["sonar:project"] {
				values := make([]string, 0, len(permissions))
				for permission := range permissions {
					values = append(values, permission)
				}
				slices.Sort(values)
				entries = append(entries, map[string]any{"login": login, "permissions": values})
			}
			sonarState.Unlock()
			sort.Slice(entries, func(i, j int) bool {
				return entries[i]["login"].(string) < entries[j]["login"].(string)
			})
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"users":  entries,
				"paging": map[string]int{"pageIndex": 1, "pageSize": 100, "total": len(entries)},
			})

		case "/sonar/api/users/search":
			_, _ = io.WriteString(writer, `{"users":[{"id":"1","login":"alice","name":"Alice",`+
				`"externalProvider":"gitlab","externalIdentity":"alice","active":true},`+
				`{"id":"2","login":"bob","name":"Bob","externalProvider":"gitlab",`+
				`"externalIdentity":"bob","active":true}],`+
				`"paging":{"pageIndex":1,"pageSize":100,"total":2}}`)

		case "/sonar/api/components/show":
			sonarState.Lock()
			visibility := sonarState.visibility
			sonarState.Unlock()
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"component": map[string]string{"key": "sonar:project", "visibility": visibility},
			})

		case "/sonar/api/permissions/add_user", "/sonar/api/permissions/remove_user":
			if err := request.ParseForm(); err != nil {
				http.Error(writer, "invalid form", http.StatusBadRequest)
				return
			}

			login := request.Form.Get("login")
			permission := request.Form.Get("permission")
			sonarState.Lock()
			if sonarState.permissions["sonar:project"][login] == nil {
				sonarState.permissions["sonar:project"][login] = make(map[string]bool)
			}
			if request.URL.Path == "/sonar/api/permissions/add_user" {
				sonarState.permissions["sonar:project"][login][permission] = true
				sonarState.writes = append(sonarState.writes, "grant:"+login+":"+permission)
			} else {
				delete(sonarState.permissions["sonar:project"][login], permission)
				sonarState.writes = append(sonarState.writes, "revoke:"+login+":"+permission)
			}
			sonarState.Unlock()
			writer.WriteHeader(http.StatusNoContent)

		case "/sonar/api/projects/update_visibility":
			if err := request.ParseForm(); err != nil {
				http.Error(writer, "invalid form", http.StatusBadRequest)
				return
			}

			sonarState.Lock()
			sonarState.visibility = request.Form.Get("visibility")
			sonarState.writes = append(sonarState.writes, "visibility:"+sonarState.visibility)
			sonarState.Unlock()
			writer.WriteHeader(http.StatusNoContent)

		default:
			http.NotFound(writer, request)
		}
	}))
	defer sonarServer.Close()

	gitLabURL := mustParseURL(t, gitLabServer.URL+"/gitlab")
	sonarURL := mustParseURL(t, sonarServer.URL+"/sonar")
	gitLabClient, err := gitlab.New(gitLabURL, "service-token", "guassp/integration")
	if err != nil {
		t.Fatalf("gitlab.New: %v", err)
	}
	sonarClient, err := sonar.New(sonarURL, "sonar-token", "guassp/integration")
	if err != nil {
		t.Fatalf("sonar.New: %v", err)
	}
	index, err := discovery.NewBindingIndex(sonarClient, "")
	if err != nil {
		t.Fatalf("discovery.NewBindingIndex: %v", err)
	}
	directory, err := reconcile.NewUserDirectory(sonarClient)
	if err != nil {
		t.Fatalf("reconcile.NewUserDirectory: %v", err)
	}
	matcher, err := reconcile.NewUserMatcher(directory, domain.UserMatchExternal, nil, nil)
	if err != nil {
		t.Fatalf("reconcile.NewUserMatcher: %v", err)
	}
	observer := observability.New("test", "integration", false)
	reconciler, err := reconcile.NewReconciler(
		gitLabClient,
		sonarClient,
		index,
		directory,
		matcher,
		reconcile.Options{
			Logger:             zerolog.New(io.Discard),
			PermissionObserver: observer,
			PermissionMap:      domain.DefaultPermissionMap(),
			Visibility: domain.VisibilityPolicy{
				Mode:    domain.VisibilityMap,
				Mapping: domain.DefaultVisibilityMap(),
			},
		},
	)
	if err != nil {
		t.Fatalf("reconcile.NewReconciler: %v", err)
	}
	projectScheduler, err := scheduler.New(1, reconciler, zerolog.New(io.Discard), observer.RecordRun)
	if err != nil {
		t.Fatalf("scheduler.New: %v", err)
	}
	observer.SetSchedulerStats(projectScheduler)
	handler, err := web.NewServer(gitLabClient, projectScheduler, zerolog.New(io.Discard), web.Options{
		GitLabBaseURL: gitLabURL,
		Observability: observer,
		SyncRate:      rate.Limit{Disabled: true},
	})
	if err != nil {
		t.Fatalf("web.NewServer: %v", err)
	}
	serviceContext, cancel := context.WithCancel(context.Background())
	if err := projectScheduler.Start(serviceContext); err != nil {
		cancel()
		t.Fatalf("scheduler.Start: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		projectScheduler.Cancel()
		<-projectScheduler.Done()
	})

	trigger := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/sync", nil)
		request.Header.Set("JOB-TOKEN", "ci-token")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	for run := 1; run <= 2; run++ {
		response := trigger()
		if response.Code != http.StatusAccepted {
			t.Fatalf("CI trigger %d status=%d body=%s", run, response.Code, response.Body.String())
		}
		waitForRunCount(t, observer, run)
	}

	sonarState.Lock()
	writes := slices.Clone(sonarState.writes)
	permissions := sonarState.permissions["sonar:project"]
	visibility := sonarState.visibility
	sonarState.Unlock()
	slices.Sort(writes)
	wantWrites := []string{
		"grant:alice:codeviewer",
		"grant:alice:issueadmin",
		"revoke:alice:admin",
		"revoke:bob:user",
		"visibility:public",
	}
	if !slices.Equal(writes, wantWrites) {
		t.Fatalf("Sonar writes = %v, want %v", writes, wantWrites)
	}
	if !permissions["alice"]["scan"] || permissions["alice"]["codeviewer"] != true ||
		permissions["alice"]["issueadmin"] != true || visibility != "public" {
		t.Fatalf("final Sonar state permissions=%v visibility=%q", permissions, visibility)
	}

	runRequest := httptest.NewRequest(http.MethodGet, "/api/v1/runs?limit=10", nil)
	runResponse := httptest.NewRecorder()
	handler.ServeHTTP(runResponse, runRequest)
	if runResponse.Code != http.StatusOK {
		t.Fatalf("run history status=%d body=%s", runResponse.Code, runResponse.Body.String())
	}

	var history struct {
		Runs []observability.Run `json:"runs"`
	}
	if err := json.NewDecoder(runResponse.Body).Decode(&history); err != nil {
		t.Fatalf("decode run history: %v", err)
	}
	runs := history.Runs
	if len(runs) != 2 || runs[0].Result != "success" || runs[1].Result != "success" ||
		runs[0].GitLabProjectID != 123 || runs[1].GitLabProjectID != 123 ||
		runs[0].Counts.Grants != 0 || runs[0].Counts.Revokes != 0 ||
		runs[1].Counts.Grants != 2 || runs[1].Counts.Revokes != 2 {
		t.Fatalf("recorded runs = %+v", runs)
	}
}

func mustParseURL(t *testing.T, value string) *url.URL {
	t.Helper()

	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", value, err)
	}

	return parsed
}

func waitForRunCount(t *testing.T, observer *observability.Service, count int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(observer.Runs(10)) >= count {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("completed run count = %d, want %d", len(observer.Runs(10)), count)
}
