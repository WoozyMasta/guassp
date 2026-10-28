// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/woozymasta/guassp/internal/gitlab"
	"github.com/woozymasta/guassp/internal/httpclient"
	"github.com/woozymasta/guassp/internal/observability"
	"github.com/woozymasta/guassp/internal/rate"
	"github.com/woozymasta/guassp/internal/reconcile"
	"github.com/woozymasta/guassp/internal/scheduler"
)

type fakeJobValidator struct {
	job              gitlab.Job
	err              error
	token            string
	calls            int
	project          gitlab.Project
	projectErr       error
	projectReference string
	projectCalls     int
}

// CurrentJob records the provided token and returns the configured response.
func (validator *fakeJobValidator) CurrentJob(_ context.Context, token string) (gitlab.Job, error) {
	validator.calls++
	validator.token = token
	return validator.job, validator.err
}

// Project records the reference and returns the configured GitLab project.
func (validator *fakeJobValidator) Project(_ context.Context, reference string) (gitlab.Project, error) {
	validator.projectCalls++
	validator.projectReference = reference
	if validator.project.ID == 0 && validator.projectErr == nil {
		return gitlab.Project{ID: 123, PathWithNamespace: "group/project"}, nil
	}
	return validator.project, validator.projectErr
}

type fakeSyncScheduler struct {
	submission scheduler.Submission
	err        error
	projectID  int64
	priority   scheduler.Priority
	source     string
	calls      int
}

// fixedFullSyncStatus provides a stable full-sync state to page tests.
type fixedFullSyncStatus struct {
	status  scheduler.FullSyncStatus
	trigger func() bool
}

// Status returns the configured full-sync state.
func (provider fixedFullSyncStatus) Status() scheduler.FullSyncStatus {
	return provider.status
}

// Trigger invokes the configured manual full-sync behavior.
func (provider fixedFullSyncStatus) Trigger() bool {
	return provider.trigger != nil && provider.trigger()
}

// Submit records one scheduling request and returns its configured result.
func (queue *fakeSyncScheduler) Submit(
	projectID int64,
	priority scheduler.Priority,
	source string,
) (scheduler.Submission, error) {
	queue.calls++
	queue.projectID = projectID
	queue.priority = priority
	queue.source = source
	return queue.submission, queue.err
}

func TestCIEndpointValidatesTokenAndUsesGitLabProjectID(t *testing.T) {
	validator := &fakeJobValidator{job: gitlab.Job{ID: 55, Project: gitlab.JobProject{ID: 123}}}
	queue := &fakeSyncScheduler{submission: scheduler.Submission{Accepted: true}}
	server := newTestServer(t, validator, queue, Options{})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/sync", strings.NewReader(`{"project_id":999}`))
	request.Header.Set("JOB-TOKEN", "ci-secret-token")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusAccepted, recorder.Body.String())
	}
	response := decodeSyncResponse(t, recorder)
	if response.ProjectID != 123 || response.Source != "ci" || response.Status != "queued" || response.Coalesced {
		t.Fatalf("response = %+v", response)
	}
	if validator.calls != 1 || validator.token != "ci-secret-token" {
		t.Fatalf("validator calls=%d token=%q", validator.calls, validator.token)
	}
	if queue.calls != 1 || queue.projectID != 123 || queue.priority != scheduler.PriorityHigh || queue.source != "ci" {
		t.Fatalf("queue = %+v", queue)
	}
}

func TestObservabilityEndpointsAreAvailable(t *testing.T) {
	validator := &fakeJobValidator{}
	queue := &fakeSyncScheduler{}
	server := newTestServer(t, validator, queue, Options{BuildVersion: "1.2.3", BuildCommit: "abc"})

	for _, path := range []string{"/metrics", "/api/v1/status", "/api/v1/runs?limit=1"} {
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Errorf("GET %s status=%d body=%s", path, recorder.Code, recorder.Body.String())
		}
	}

	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/runs?limit=0", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid run limit status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestManualFullSyncEndpointIsOptInAndCoalescesRequests(t *testing.T) {
	validator := &fakeJobValidator{}
	queue := &fakeSyncScheduler{}
	disabled := newTestServer(t, validator, queue, Options{})
	missing := httptest.NewRecorder()
	disabled.ServeHTTP(missing, httptest.NewRequest(http.MethodPost, "/api/v1/full-sync", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("disabled endpoint status=%d, want 404", missing.Code)
	}

	accepted := true
	controller := fixedFullSyncStatus{trigger: func() bool {
		if !accepted {
			return false
		}
		accepted = false
		return true
	}}

	server := newTestServer(t, validator, queue, Options{
		APIToken: "api-secret", EnableManualFullSync: true, FullSync: controller,
	})
	unauthorized := httptest.NewRecorder()
	server.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/api/v1/full-sync", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized endpoint status=%d, want 401", unauthorized.Code)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/full-sync", nil)
	request.Header.Set("Authorization", "Bearer api-secret")
	result := httptest.NewRecorder()
	server.ServeHTTP(result, request)
	if result.Code != http.StatusAccepted || !strings.Contains(result.Body.String(), `"status":"queued"`) {
		t.Fatalf("first trigger status=%d body=%s", result.Code, result.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/full-sync", nil)
	request.Header.Set("Authorization", "Bearer api-secret")
	result = httptest.NewRecorder()
	server.ServeHTTP(result, request)
	if result.Code != http.StatusConflict {
		t.Fatalf("duplicate trigger status=%d, want 409; body=%s", result.Code, result.Body.String())
	}
}

func TestManualFullSyncWebActionUsesExistingWebAuthentication(t *testing.T) {
	triggered := false
	controller := fixedFullSyncStatus{trigger: func() bool {
		triggered = true
		return true
	}}

	server := newTestServer(t, &fakeJobValidator{}, &fakeSyncScheduler{}, Options{
		BasicUser: "operator", BasicPassword: "password",
		EnableManualFullSync: true, FullSync: controller,
	})

	pageRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	pageRequest.SetBasicAuth("operator", "password")
	page := httptest.NewRecorder()
	server.ServeHTTP(page, pageRequest)
	if page.Code != http.StatusOK ||
		!strings.Contains(page.Body.String(), "Queue full synchronization") ||
		!strings.Contains(page.Body.String(), "/api/v1/full-sync") {
		t.Fatalf("home page status=%d body=%s", page.Code, page.Body.String())
	}

	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("action=full_sync"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("operator", "password")
	result := httptest.NewRecorder()
	server.ServeHTTP(result, request)
	if result.Code != http.StatusAccepted || !triggered ||
		!strings.Contains(result.Body.String(), "Full synchronization queued") {
		t.Fatalf("web action status=%d triggered=%t body=%s", result.Code, triggered, result.Body.String())
	}
}

func TestSSRPagesProtectManualFormAndQueueProject(t *testing.T) {
	validator := &fakeJobValidator{
		project: gitlab.Project{ID: 321, PathWithNamespace: "<script>alert(1)</script>"},
	}
	queue := &fakeSyncScheduler{submission: scheduler.Submission{Accepted: true, Coalesced: true}}
	observer := observability.New("1.0.0", "abc", false)
	observer.RecordRun(scheduler.Run{
		ProjectID: 55,
		Source:    "ci",
		Result: reconcile.Result{
			Status: reconcile.StatusSuccess,
			Counts: reconcile.Counts{Grants: 2, Revokes: 1, Targets: 3},
			Errors: []string{"sensitive upstream detail"},
		},
	})
	server := newTestServer(t, validator, queue, Options{
		BasicUser: "operator", BasicPassword: "password", Observability: observer,
		FullSync: fixedFullSyncStatus{status: scheduler.FullSyncStatus{
			StartedAt: time.Now(), FinishedAt: time.Now(), NextAt: time.Now().Add(time.Hour),
		}},
	})

	form := httptest.NewRecorder()
	server.ServeHTTP(form, httptest.NewRequest(http.MethodGet, "/", nil))
	if form.Code != http.StatusUnauthorized || form.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("unauthenticated form status=%d headers=%v", form.Code, form.Header())
	}

	stats := httptest.NewRecorder()
	server.ServeHTTP(stats, httptest.NewRequest(http.MethodGet, "/stats", nil))
	if stats.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated stats status=%d, want 401", stats.Code)
	}

	statsRequest := httptest.NewRequest(http.MethodGet, "/stats", nil)
	statsRequest.SetBasicAuth("operator", "password")
	stats = httptest.NewRecorder()
	server.ServeHTTP(stats, statsRequest)
	statsBody := stats.Body.String()
	if stats.Code != http.StatusOK || !strings.Contains(statsBody, "GUASSP | Statistics") ||
		!strings.Contains(statsBody, `<dt>Success</dt><dd class="state-good">1</dd>`) ||
		!strings.Contains(statsBody, "<dt>Permission grants</dt><dd>2</dd>") ||
		!strings.Contains(statsBody, "Next run") ||
		strings.Contains(statsBody, "sensitive upstream detail") {
		t.Fatalf("authenticated stats status=%d body=%s", stats.Code, stats.Body.String())
	}
	if stats.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("stats response did not set a content security policy")
	}

	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("project=group%2Fproject"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("operator", "password")
	result := httptest.NewRecorder()
	server.ServeHTTP(result, request)
	if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), "Synchronization queued") ||
		!strings.Contains(result.Body.String(), "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("form submit status=%d body=%s", result.Code, result.Body.String())
	}
	if queue.calls != 1 || queue.source != "manual" || !queue.submission.Coalesced {
		t.Fatalf("queue = %+v", queue)
	}
}

func TestWebDisabledLeavesJSONRoutesEnabled(t *testing.T) {
	server := newTestServer(t, &fakeJobValidator{}, &fakeSyncScheduler{}, Options{DisableWeb: true})
	for _, path := range []string{"/", "/stats"} {
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Errorf("GET %s status=%d, want 404", path, recorder.Code)
		}
	}
	health := httptest.NewRecorder()
	server.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status=%d, want 200", health.Code)
	}
	manual := httptest.NewRecorder()
	server.ServeHTTP(manual, manualJSONRequest(`{"project":"42"}`))
	if manual.Code != http.StatusNotFound {
		t.Fatalf("manual API status=%d, want 404", manual.Code)
	}
	ci := httptest.NewRecorder()
	server.ServeHTTP(ci, httptest.NewRequest(http.MethodPost, "/api/v1/sync", nil))
	if ci.Code != http.StatusUnauthorized {
		t.Fatalf("CI API status=%d, want 401", ci.Code)
	}
}

func TestSSRManualFormUsesConfiguredRateLimit(t *testing.T) {
	validator := &fakeJobValidator{}
	queue := &fakeSyncScheduler{submission: scheduler.Submission{Accepted: true}}
	server := newTestServer(t, validator, queue, Options{
		SyncRate: rate.Limit{Requests: 1, Window: time.Minute},
	})
	form := httptest.NewRecorder()
	server.ServeHTTP(form, httptest.NewRequest(http.MethodGet, "/", nil))
	if form.Code != http.StatusOK || !strings.Contains(form.Body.String(), `<form method="post" action="/">`) {
		t.Fatalf("form page status=%d body=%s", form.Code, form.Body.String())
	}
	post := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("project=123"))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		return recorder
	}
	if response := post(); response.Code != http.StatusOK {
		t.Fatalf("first form submit status=%d body=%s", response.Code, response.Body.String())
	}
	response := post()
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
		t.Fatalf("limited form submit status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}

func TestCIEndpointAcceptsBearerAndReturnsCoalesced202(t *testing.T) {
	validator := &fakeJobValidator{job: gitlab.Job{ID: 55, Project: gitlab.JobProject{ID: 123}}}
	queue := &fakeSyncScheduler{submission: scheduler.Submission{Accepted: true, Coalesced: true}}
	server := newTestServer(t, validator, queue, Options{})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/sync", nil)
	request.Header.Set("Authorization", "bEaReR ci-secret-token")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusAccepted, recorder.Body.String())
	}
	response := decodeSyncResponse(t, recorder)
	if !response.Coalesced || queue.calls != 1 || validator.token != "ci-secret-token" {
		t.Fatalf("response = %+v; queue=%+v; token=%q", response, queue, validator.token)
	}
}

func TestCIEndpointControlsLegacyBodyToken(t *testing.T) {
	body := `{"job_token":"ci-secret-token"}`
	t.Run("disabled by default", func(t *testing.T) {
		validator := &fakeJobValidator{}
		server := newTestServer(t, validator, &fakeSyncScheduler{}, Options{})
		request := jsonRequest(body)
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized || validator.calls != 0 {
			t.Fatalf("status=%d validator calls=%d", recorder.Code, validator.calls)
		}
	})

	t.Run("enabled by compatibility option", func(t *testing.T) {
		validator := &fakeJobValidator{job: gitlab.Job{ID: 55, Project: gitlab.JobProject{ID: 123}}}
		queue := &fakeSyncScheduler{submission: scheduler.Submission{Accepted: true}}
		server := newTestServer(t, validator, queue, Options{AllowJobTokenBody: true})
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, jsonRequest(body))
		if recorder.Code != http.StatusAccepted || validator.token != "ci-secret-token" {
			t.Fatalf("status=%d token=%q body=%s", recorder.Code, validator.token, recorder.Body.String())
		}
	})
}

func TestCIEndpointRejectsCallerProjectIDInCompatibilityBody(t *testing.T) {
	validator := &fakeJobValidator{}
	server := newTestServer(t, validator, &fakeSyncScheduler{}, Options{AllowJobTokenBody: true})
	request := jsonRequest(`{"job_token":"ci-secret-token","project_id":999}`)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest || validator.calls != 0 {
		t.Fatalf("status=%d validator calls=%d body=%s", recorder.Code, validator.calls, recorder.Body.String())
	}
}

func TestCIEndpointRejectsMalformedTokenTransportBeforeGitLab(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
	}{
		{name: "invalid authorization scheme", headers: http.Header{"Authorization": {"Basic token"}}},
		{name: "multiple transports", headers: http.Header{"Job-Token": {"token"}, "Authorization": {"Bearer token"}}},
		{name: "multiple job token headers", headers: http.Header{"Job-Token": {"one", "two"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validator := &fakeJobValidator{}
			server := newTestServer(t, validator, &fakeSyncScheduler{}, Options{})
			request := httptest.NewRequest(http.MethodPost, "/api/v1/sync", nil)
			request.Header = test.headers
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest || validator.calls != 0 {
				t.Fatalf("status=%d validator calls=%d", recorder.Code, validator.calls)
			}
		})
	}
}

func TestCIEndpointBoundsCompatibilityBody(t *testing.T) {
	validator := &fakeJobValidator{}
	server := newTestServer(t, validator, &fakeSyncScheduler{}, Options{AllowJobTokenBody: true})
	request := jsonRequest(`{"job_token":"` + strings.Repeat("a", maxCIBodyBytes) + `"}`)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusRequestEntityTooLarge || validator.calls != 0 {
		t.Fatalf("status=%d validator calls=%d", recorder.Code, validator.calls)
	}
}

func TestCIEndpointSanitizesGitLabValidationFailures(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantText   string
	}{
		{
			name: "invalid token",
			err: &httpclient.Error{
				Upstream: "gitlab", Operation: "validate job token",
				StatusCode: http.StatusUnauthorized, Err: errors.New("token=private"),
			},
			wantStatus: http.StatusUnauthorized,
			wantText:   "invalid CI job token",
		},
		{
			name:       "upstream failure",
			err:        errors.New("token=private upstream body"),
			wantStatus: http.StatusBadGateway,
			wantText:   "unable to validate CI job token",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validator := &fakeJobValidator{err: test.err}
			server := newTestServer(t, validator, &fakeSyncScheduler{}, Options{})
			request := httptest.NewRequest(http.MethodPost, "/api/v1/sync", nil)
			request.Header.Set("JOB-TOKEN", "ci-secret-token")
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus || !strings.Contains(recorder.Body.String(), test.wantText) {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "private") ||
				strings.Contains(recorder.Body.String(), "ci-secret-token") {
				t.Fatalf("sensitive value leaked: %s", recorder.Body.String())
			}
		})
	}
}

func TestCIEndpointRejectsInvalidGitLabJobAndStoppedScheduler(t *testing.T) {
	t.Run("invalid job response", func(t *testing.T) {
		validator := &fakeJobValidator{job: gitlab.Job{ID: 0, Project: gitlab.JobProject{ID: 123}}}
		queue := &fakeSyncScheduler{}
		server := newTestServer(t, validator, queue, Options{})
		request := httptest.NewRequest(http.MethodPost, "/api/v1/sync", nil)
		request.Header.Set("JOB-TOKEN", "ci-secret-token")
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadGateway || queue.calls != 0 {
			t.Fatalf("status=%d queue calls=%d", recorder.Code, queue.calls)
		}
	})

	t.Run("scheduler stopped", func(t *testing.T) {
		validator := &fakeJobValidator{job: gitlab.Job{ID: 55, Project: gitlab.JobProject{ID: 123}}}
		queue := &fakeSyncScheduler{}
		server := newTestServer(t, validator, queue, Options{})
		request := httptest.NewRequest(http.MethodPost, "/api/v1/sync", nil)
		request.Header.Set("JOB-TOKEN", "ci-secret-token")
		queue.submission = scheduler.Submission{Accepted: false}
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusServiceUnavailable || queue.calls != 1 {
			t.Fatalf("status=%d queue calls=%d", recorder.Code, queue.calls)
		}
	})
}

func TestHealthAndReadinessRoutes(t *testing.T) {
	server := newTestServer(t, &fakeJobValidator{}, &fakeSyncScheduler{}, Options{})
	for _, path := range []string{"/healthz"} {
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"status":"ok"`) ||
			recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s status=%d headers=%v body=%s", path, recorder.Code, recorder.Header(), recorder.Body.String())
		}
	}
	removedAlias := httptest.NewRecorder()
	server.ServeHTTP(removedAlias, httptest.NewRequest(http.MethodGet, "/health", nil))
	if removedAlias.Code != http.StatusNotFound {
		t.Fatalf("removed health alias status=%d, want %d", removedAlias.Code, http.StatusNotFound)
	}
	readiness := httptest.NewRecorder()
	server.ServeHTTP(readiness, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if readiness.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness before initialization = %d", readiness.Code)
	}
	server.MarkReady()
	readiness = httptest.NewRecorder()
	server.ServeHTTP(readiness, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if readiness.Code != http.StatusOK {
		t.Fatalf("readiness after initialization = %d", readiness.Code)
	}
}

// newTestServer constructs a test handler with a disabled logger.
func newTestServer(
	t *testing.T,
	validator GitLabClient,
	queue SyncScheduler,
	options Options,
) *Server {
	t.Helper()
	if options.GitLabBaseURL == nil {
		options.GitLabBaseURL, _ = url.Parse("https://gitlab.example.com")
	}
	if options.SyncRate == (rate.Limit{}) {
		options.SyncRate = rate.Limit{Disabled: true}
	}
	server, err := NewServer(validator, queue, zerolog.Nop(), options)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	return server
}

// jsonRequest creates a sync request using the compatibility JSON transport.
func jsonRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/sync", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

// decodeSyncResponse parses a successful CI response for assertions.
func decodeSyncResponse(t *testing.T, recorder *httptest.ResponseRecorder) SyncResponse {
	t.Helper()
	var response SyncResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode sync response: %v", err)
	}

	return response
}
