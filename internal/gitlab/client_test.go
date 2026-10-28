// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/woozymasta/guassp/internal/httpclient"
)

type observedRequest struct {
	upstream    string
	operation   string
	statusClass string
	duration    time.Duration
}

type requestObserverCapture struct {
	requests []observedRequest
}

func (observer *requestObserverCapture) ObserveRequest(
	upstream, operation, statusClass string,
	duration time.Duration,
) {
	observer.requests = append(observer.requests, observedRequest{
		upstream:    upstream,
		operation:   operation,
		statusClass: statusClass,
		duration:    duration,
	})
}

// newTestClient constructs a GitLab client for an httptest server.
func newTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	baseURL, err := url.Parse(server.URL + "/gitlab")
	if err != nil {
		t.Fatalf("parse test base URL: %v", err)
	}
	client, err := New(baseURL, "service-secret", "guassp/test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return client
}

func TestAPIErrorReturnsNilForSuccessfulSDKCall(t *testing.T) {
	client := &Client{}
	if err := client.apiError("get project", nil); err != nil {
		t.Fatalf("apiError(nil) = %v, want nil", err)
	}
}

func TestObserverReportsSuccessfulGitLabRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"id":42,"name":"project"}`))
	}))
	t.Cleanup(server.Close)
	client := newTestClient(t, server)
	observer := &requestObserverCapture{}
	client.SetObserver(observer)

	if _, err := client.Project(context.Background(), "42"); err != nil {
		t.Fatalf("Project: %v", err)
	}
	if len(observer.requests) != 1 {
		t.Fatalf("observed requests = %d, want 1", len(observer.requests))
	}

	request := observer.requests[0]
	if request.upstream != "gitlab" || request.operation != "get project" ||
		request.statusClass != "2xx" || request.duration <= 0 {
		t.Fatalf("observed request = %+v", request)
	}
}

func TestNilGitLabResponsesReturnErrorsAndReportFailure(t *testing.T) {
	tests := []struct {
		name string
		call func(*Client) error
	}{
		{
			name: "project",
			call: func(client *Client) error {
				_, err := client.Project(context.Background(), "42")
				return err
			},
		},
		{
			name: "user",
			call: func(client *Client) error {
				_, err := client.User(context.Background(), 42)
				return err
			},
		},
		{
			name: "job",
			call: func(client *Client) error {
				_, err := client.CurrentJob(context.Background(), "job-token")
				return err
			},
		},
		{
			name: "project member",
			call: func(client *Client) error {
				_, err := client.ProjectMembers(context.Background(), 42)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if strings.HasSuffix(request.URL.Path, "/members/all") {
					_, _ = writer.Write([]byte(`[null]`))
					return
				}
				_, _ = writer.Write([]byte(`null`))
			}))
			t.Cleanup(server.Close)
			client := newTestClient(t, server)
			observer := &requestObserverCapture{}
			client.SetObserver(observer)

			if err := test.call(client); err == nil {
				t.Fatal("accepted a null API response")
			}
			if len(observer.requests) != 1 || observer.requests[0].statusClass != "error" {
				t.Fatalf("observations = %+v, want one error", observer.requests)
			}
		})
	}
}

func TestCurrentJobUsesJobTokenAndBasePath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || req.URL.Path != "/gitlab/api/v4/job" {
			t.Errorf("request = %s %s", req.Method, req.URL.Path)
		}
		if req.Header.Get("JOB-TOKEN") != "ci-secret" {
			t.Errorf("JOB-TOKEN = %q", req.Header.Get("JOB-TOKEN"))
		}
		if req.Header.Get("PRIVATE-TOKEN") != "" {
			t.Errorf("PRIVATE-TOKEN = %q", req.Header.Get("PRIVATE-TOKEN"))
		}
		if req.Header.Get("User-Agent") != "guassp/test" {
			t.Errorf("User-Agent = %q", req.Header.Get("User-Agent"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":123,"project":{"id":456}}`))
	}))
	t.Cleanup(server.Close)
	client := newTestClient(t, server)

	job, err := client.CurrentJob(context.Background(), "ci-secret")
	if err != nil {
		t.Fatalf("CurrentJob: %v", err)
	}
	if job.ID != 123 || job.Project.ID != 456 {
		t.Fatalf("job = %#v", job)
	}
}

func TestCurrentJobAuthenticationFailureIsSanitized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("JOB-TOKEN") != "invalid-ci-secret" {
			t.Errorf("JOB-TOKEN = %q", req.Header.Get("JOB-TOKEN"))
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("response-body-secret"))
	}))
	t.Cleanup(server.Close)
	client := newTestClient(t, server)

	_, err := client.CurrentJob(context.Background(), "invalid-ci-secret")
	var apiErr *httpclient.Error
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden {
		t.Fatalf("error = %#v", err)
	}
	if strings.Contains(err.Error(), "response-body-secret") ||
		strings.Contains(err.Error(), "invalid-ci-secret") {
		t.Fatalf("error leaked a secret: %v", err)
	}
}

func TestCurrentJobRequiresProjectID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":123,"project":{}}`))
	}))
	t.Cleanup(server.Close)
	client := newTestClient(t, server)

	_, err := client.CurrentJob(context.Background(), "ci-secret")
	var apiErr *httpclient.Error
	if !errors.As(err, &apiErr) || apiErr.Err == nil {
		t.Fatalf("CurrentJob error = %#v", err)
	}
}

func TestCurrentJobDoesNotUseLegacyPipelineProjectID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":123,"pipeline":{"project_id":456}}`))
	}))
	t.Cleanup(server.Close)
	client := newTestClient(t, server)

	_, err := client.CurrentJob(context.Background(), "ci-secret")
	var apiErr *httpclient.Error
	if !errors.As(err, &apiErr) || apiErr.Err == nil {
		t.Fatalf("CurrentJob error = %#v, want missing modern project ID error", err)
	}
}

func TestProjectFetchesNumericAndEscapedPathReferences(t *testing.T) {
	wantPaths := []string{
		"/gitlab/api/v4/projects/42",
		"/gitlab/api/v4/projects/group%2Fsubgroup%2Fproject",
	}
	var index atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotIndex := int(index.Add(1)) - 1
		if gotIndex >= len(wantPaths) || req.URL.EscapedPath() != wantPaths[gotIndex] {
			wantPath := wantPaths[min(gotIndex, len(wantPaths)-1)]
			t.Errorf(
				"escaped path = %q, want %q",
				req.URL.EscapedPath(),
				wantPath,
			)
		}
		if req.Header.Get("PRIVATE-TOKEN") != "service-secret" {
			t.Errorf("PRIVATE-TOKEN = %q", req.Header.Get("PRIVATE-TOKEN"))
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":42,
			"name":"project",
			"path_with_namespace":"group/project",
			"web_url":"https://gitlab.example/group/project",
			"visibility":"private"
		}`))
	}))
	t.Cleanup(server.Close)
	client := newTestClient(t, server)

	for _, reference := range []string{"42", "group/subgroup/project"} {
		project, err := client.Project(context.Background(), reference)
		if err != nil {
			t.Fatalf("Project(%q): %v", reference, err)
		}
		if project.ID != 42 || project.Visibility != "private" {
			t.Fatalf("project = %#v", project)
		}
	}
}

func TestProjectMembersPaginatesEffectiveMembers(t *testing.T) {
	var requestedPages []int
	var requestedPagesMu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/gitlab/api/v4/projects/456/members/all" {
			t.Errorf("path = %q", req.URL.Path)
		}
		if req.URL.Query().Get("per_page") != "100" {
			t.Errorf("per_page = %q", req.URL.Query().Get("per_page"))
		}

		page, err := strconv.Atoi(req.URL.Query().Get("page"))
		if err != nil {
			t.Errorf("page query: %v", err)
		}

		requestedPagesMu.Lock()
		requestedPages = append(requestedPages, page)
		requestedPagesMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if page == 1 {
			w.Header().Set("X-Next-Page", "2")
			members := make([]Member, 100)
			for i := range members {
				members[i] = Member{ID: int64(i + 1), Username: fmt.Sprintf("user-%d", i+1), AccessLevel: 10}
			}
			_ = json.NewEncoder(w).Encode(members)
			return
		}

		_, _ = w.Write([]byte(`[
			{"id":101,"username":"last","name":"Last User","state":"active","access_level":15}
		]`))
	}))
	t.Cleanup(server.Close)
	client := newTestClient(t, server)

	members, err := client.ProjectMembers(context.Background(), 456)
	if err != nil {
		t.Fatalf("ProjectMembers: %v", err)
	}
	if len(members) != 101 || members[100].AccessLevel != 15 || members[100].State != "active" {
		t.Fatalf("members count/final member = %d/%#v", len(members), members[len(members)-1])
	}

	requestedPagesMu.Lock()
	defer requestedPagesMu.Unlock()
	if !slices.Equal(requestedPages, []int{1, 2}) {
		t.Fatalf("requested pages = %v", requestedPages)
	}
}

func TestUserFetchesLegacyEmailFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/gitlab/api/v4/users/19" {
			t.Errorf("path = %q", req.URL.Path)
		}
		if req.Header.Get("PRIVATE-TOKEN") != "service-secret" {
			t.Errorf("PRIVATE-TOKEN = %q", req.Header.Get("PRIVATE-TOKEN"))
		}
		_, _ = w.Write([]byte(`{
			"id":19,
			"username":"legacy",
			"name":"Legacy User",
			"email":"legacy@example.com"
		}`))
	}))
	t.Cleanup(server.Close)
	client := newTestClient(t, server)

	user, err := client.User(context.Background(), 19)
	if err != nil {
		t.Fatalf("User: %v", err)
	}
	if user.Email != "legacy@example.com" || user.ID != 19 {
		t.Fatalf("user = %#v", user)
	}
}

func TestTransientGETRetriesAndSanitizesHTTPError(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("PRIVATE-TOKEN") != "service-secret" {
			t.Errorf("PRIVATE-TOKEN = %q", req.Header.Get("PRIVATE-TOKEN"))
		}
		if attempts.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("response-body-secret"))
			return
		}
		_, _ = w.Write([]byte(`{"id":42,"name":"project"}`))
	}))
	t.Cleanup(server.Close)
	client := newTestClient(t, server)
	if _, err := client.Project(context.Background(), "42"); err != nil {
		t.Fatalf("Project after retry: %v", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}

	var clientErrorAttempts atomic.Int32
	clientErrorServer := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			clientErrorAttempts.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("response-body-secret"))
		}),
	)
	t.Cleanup(clientErrorServer.Close)
	clientError := newTestClient(t, clientErrorServer)
	_, err := clientError.Project(context.Background(), "42")
	if err == nil {
		t.Fatal("Project accepted unauthorized response")
	}

	var apiErr *httpclient.Error
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("error = %#v", err)
	}
	if strings.Contains(err.Error(), "response-body-secret") ||
		strings.Contains(err.Error(), "service-secret") {
		t.Fatalf("error leaked a secret: %v", err)
	}
	if got := clientErrorAttempts.Load(); got != 1 {
		t.Fatalf("unauthorized attempts = %d, want 1", got)
	}
}

func TestCrossOriginRedirectDoesNotForwardCredentials(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		targetHits.Add(1)
		if req.Header.Get("PRIVATE-TOKEN") != "" {
			t.Errorf("service token forwarded to redirect target")
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, target.URL+"/stolen", http.StatusFound)
	}))
	t.Cleanup(origin.Close)
	client := newTestClient(t, origin)

	_, err := client.Project(context.Background(), "42")
	if !errors.Is(err, httpclient.ErrCrossOriginRedirect) {
		t.Fatalf("redirect error = %v", err)
	}
	if strings.Contains(err.Error(), "service-secret") || targetHits.Load() != 0 {
		t.Fatalf(
			"redirect leaked credentials or reached target: error=%v target hits=%d",
			err,
			targetHits.Load(),
		)
	}
}

func TestSameOriginRedirectCannotLeaveBasePath(t *testing.T) {
	var outsideHits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/other" {
			outsideHits.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, req, "/other", http.StatusFound)
	}))
	t.Cleanup(server.Close)
	client := newTestClient(t, server)

	_, err := client.Project(context.Background(), "42")
	if !errors.Is(err, httpclient.ErrBasePathRedirect) {
		t.Fatalf("redirect error = %v", err)
	}
	if outsideHits.Load() != 0 {
		t.Fatalf("request escaped base path %d times", outsideHits.Load())
	}
}

func TestTransportErrorRetries(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Errorf("response writer does not support hijacking")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			connection, _, err := hijacker.Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			_ = connection.Close()
			return
		}
		_, _ = w.Write([]byte(`{"id":42,"name":"project"}`))
	}))
	t.Cleanup(server.Close)
	client := newTestClient(t, server)

	if _, err := client.Project(context.Background(), "42"); err != nil {
		t.Fatalf("Project after transport retry: %v", err)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
}
