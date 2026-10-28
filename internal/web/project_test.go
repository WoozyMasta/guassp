// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/woozymasta/guassp/internal/gitlab"
	"github.com/woozymasta/guassp/internal/rate"
	"github.com/woozymasta/guassp/internal/scheduler"
)

func TestProjectResolverAcceptsIDPathAndCanonicalURL(t *testing.T) {
	baseURL, err := url.Parse("https://gitlab.example.com/gitlab")
	if err != nil {
		t.Fatalf("parse GitLab base URL: %v", err)
	}
	lookup := &fakeJobValidator{project: gitlab.Project{ID: 42, PathWithNamespace: "group/sub/project"}}
	resolver, err := newProjectResolver(lookup, baseURL)
	if err != nil {
		t.Fatalf("newProjectResolver: %v", err)
	}
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "42", want: "42"},
		{input: "/group/sub/project/", want: "group/sub/project"},
		{input: "https://gitlab.example.com/gitlab/group/sub/project", want: "group/sub/project"},
	} {
		project, resolveErr := resolver.Resolve(context.Background(), test.input)
		if resolveErr != nil || project.ID != 42 || lookup.projectReference != test.want {
			t.Fatalf("Resolve(%q) = (%+v, %v), reference=%q", test.input, project, resolveErr,
				lookup.projectReference)
		}
	}
}

func TestProjectResolverRejectsUnsafeURLsAndPaths(t *testing.T) {
	baseURL, _ := url.Parse("https://gitlab.example.com/gitlab")
	lookup := &fakeJobValidator{}
	resolver, err := newProjectResolver(lookup, baseURL)
	if err != nil {
		t.Fatalf("newProjectResolver: %v", err)
	}
	for _, input := range []string{
		"https://attacker.example/gitlab/group/project",
		"https://gitlab.example.com/other/group/project",
		"https://gitlab.example.com.evil/gitlab/group/project",
		"//attacker.example/group/project",
		"http:/gitlab.example.com/group/project",
		"https://gitlab.example.com/gitlab/%2e%2e/admin",
		"group/../project",
		"group//project",
		"https://gitlab.example.com/gitlab/group/project?redirect=https://attacker.example",
	} {
		if _, resolveErr := resolver.Resolve(context.Background(), input); resolveErr == nil {
			t.Errorf("Resolve(%q) succeeded", input)
		}
	}
	if lookup.projectCalls != 0 {
		t.Fatalf("GitLab project calls = %d, want 0 for rejected inputs", lookup.projectCalls)
	}
}

func TestManualSyncRequiresBasicAndQueuesResolvedProject(t *testing.T) {
	validator := &fakeJobValidator{}
	queue := &fakeSyncScheduler{submission: scheduler.Submission{Accepted: true, Coalesced: true}}
	server := newTestServer(t, validator, queue, Options{BasicUser: "operator", BasicPassword: "secret"})
	request := manualJSONRequest(`{"project":"group/project"}`)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized || recorder.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("unauthenticated status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body)
	}
	if validator.projectCalls != 0 || queue.calls != 0 {
		t.Fatalf("unauthenticated lookups=%d submissions=%d", validator.projectCalls, queue.calls)
	}

	request = manualJSONRequest(`{"project":"group/project"}`)
	request.SetBasicAuth("operator", "secret")
	recorder = httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted || !strings.Contains(recorder.Body.String(), `"project_id":123`) ||
		!strings.Contains(recorder.Body.String(), `"coalesced":true`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body)
	}
	if queue.projectID != 123 || queue.priority != scheduler.PriorityHigh || queue.source != "manual" {
		t.Fatalf("queue = %+v", queue)
	}
}

func TestManualSyncRateLimitUsesRemoteIP(t *testing.T) {
	validator := &fakeJobValidator{}
	queue := &fakeSyncScheduler{submission: scheduler.Submission{Accepted: true}}
	server := newTestServer(t, validator, queue, Options{SyncRate: rate.Limit{Requests: 1, Window: time.Minute}})
	first := manualJSONRequest(`{"project":"42"}`)
	first.RemoteAddr = "192.0.2.10:1234"
	first.Header.Set("X-Forwarded-For", "192.0.2.11")
	firstRecorder := httptest.NewRecorder()
	server.ServeHTTP(firstRecorder, first)
	if firstRecorder.Code != http.StatusAccepted {
		t.Fatalf("first status=%d body=%s", firstRecorder.Code, firstRecorder.Body)
	}

	second := manualJSONRequest(`{"project":"42"}`)
	second.RemoteAddr = "192.0.2.10:5678"
	second.Header.Set("X-Forwarded-For", "192.0.2.11")
	secondRecorder := httptest.NewRecorder()
	server.ServeHTTP(secondRecorder, second)
	if secondRecorder.Code != http.StatusTooManyRequests || secondRecorder.Header().Get("Retry-After") == "" {
		t.Fatalf("second status=%d headers=%v body=%s", secondRecorder.Code, secondRecorder.Header(), secondRecorder.Body)
	}
	if queue.calls != 1 {
		t.Fatalf("queue calls = %d, want 1", queue.calls)
	}
}

func TestManualSyncRejectsUnknownInputFields(t *testing.T) {
	queue := &fakeSyncScheduler{submission: scheduler.Submission{Accepted: true}}
	server := newTestServer(t, &fakeJobValidator{}, queue, Options{})
	request := manualJSONRequest(`{"project":"42","permissions":["admin"]}`)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || queue.calls != 0 {
		t.Fatalf("unknown input field status=%d queue calls=%d", recorder.Code, queue.calls)
	}
}

func TestManualSyncSanitizesUpstreamFailure(t *testing.T) {
	validator := &fakeJobValidator{projectErr: errors.New("private upstream details")}
	server := newTestServer(t, validator, &fakeSyncScheduler{}, Options{})
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, manualJSONRequest(`{"project":"42"}`))
	if recorder.Code != http.StatusBadGateway || strings.Contains(recorder.Body.String(), "private upstream") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body)
	}
}

// manualJSONRequest creates a bounded JSON manual-sync request.
func manualJSONRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/projects/sync", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}
