// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

// Package gitlab adapts the GitLab API used by Guassp.
package gitlab

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/woozymasta/guassp/internal/httpclient"
	gitlabapi "gitlab.com/gitlab-org/api/client-go/v3"
)

const (
	apiPageSize = 100
	upstream    = "gitlab"
	apiRetries  = 2
)

// Client reads jobs, projects, project members, and users from GitLab.
type Client struct {
	logger     *zerolog.Logger
	observer   httpclient.RequestObserver
	http       *httpclient.Client
	baseURL    *url.URL
	api        *gitlabapi.Client
	userAgent  string
	observerMu sync.RWMutex
}

// Job is the current CI job and its owning GitLab project.
type Job struct {
	ID      int64      `json:"id"`
	Project JobProject `json:"project"`
}

// JobProject identifies the project that owns a CI job.
type JobProject struct {
	ID int64 `json:"id"`
}

// Project contains the project fields used by Guassp.
type Project struct {
	Name              string `json:"name"`
	PathWithNamespace string `json:"path_with_namespace"`
	WebURL            string `json:"web_url"`
	Visibility        string `json:"visibility"`
	ID                int64  `json:"id"`
}

// Member contains a user's effective membership in a project.
type Member struct {
	Username    string `json:"username"`
	Name        string `json:"name"`
	State       string `json:"state"`
	ID          int64  `json:"id"`
	AccessLevel int    `json:"access_level"`
}

// User contains the identity fields needed by legacy email matching.
type User struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	ID       int64  `json:"id"`
}

// New creates a GitLab client for a parsed API base URL and service token.
func New(baseURL *url.URL, serviceToken, userAgent string) (*Client, error) {
	if serviceToken == "" {
		return nil, errors.New("GitLab service token must not be empty")
	}
	if userAgent == "" {
		return nil, errors.New("GitLab user agent must not be empty")
	}

	http, err := httpclient.New(baseURL, userAgent)
	if err != nil {
		return nil, fmt.Errorf("create GitLab HTTP client: %w", err)
	}

	normalizedBaseURL := *baseURL
	normalizedBaseURL.Path = strings.TrimRight(normalizedBaseURL.Path, "/")
	normalizedBaseURL.RawPath = strings.TrimRight(normalizedBaseURL.EscapedPath(), "/")

	client := &Client{
		http:      http,
		baseURL:   &normalizedBaseURL,
		userAgent: userAgent,
	}
	client.api, err = client.newAPIClient(serviceToken, false)
	if err != nil {
		return nil, fmt.Errorf("create GitLab API client: %w", err)
	}

	return client, nil
}

// SetObserver configures the shared HTTP client's optional request observer.
func (client *Client) SetObserver(observer httpclient.RequestObserver) {
	client.observerMu.Lock()
	client.observer = observer
	client.observerMu.Unlock()
}

// SetLogger configures safe structured logging for GitLab requests.
func (client *Client) SetLogger(logger zerolog.Logger) {
	client.observerMu.Lock()
	client.logger = &logger
	client.observerMu.Unlock()
	client.http.SetLogger(logger)
}

// Preflight verifies the service token and its GitLab API read scope.
func (client *Client) Preflight(ctx context.Context) error {
	started := time.Now()
	user, _, err := client.api.Users.CurrentUser(gitlabapi.WithContext(ctx))
	if err != nil {
		apiErr := client.apiError("validate service token", err)
		client.observe("validate service token", started, apiErr)
		return apiErr
	}
	if user == nil || user.ID < 1 {
		apiErr := client.apiError("validate service token", errors.New("response does not include a valid user ID"))
		client.observe("validate service token", started, apiErr)
		return apiErr
	}
	client.observe("validate service token", started, nil)

	membership, simple := true, true
	started = time.Now()
	projects, _, err := client.api.Projects.ListProjects(&gitlabapi.ListProjectsOptions{
		PerPage:    1,
		Membership: &membership,
		Simple:     &simple,
	}, gitlabapi.WithContext(ctx))
	if err != nil {
		apiErr := client.apiError("validate project read access", err)
		client.observe("validate project read access", started, apiErr)
		return apiErr
	}
	if projects == nil {
		apiErr := client.apiError("validate project read access", errors.New("response does not include a project list"))
		client.observe("validate project read access", started, apiErr)
		return apiErr
	}
	client.observe("validate project read access", started, nil)

	return nil
}

// CurrentJob validates a CI job token with GitLab and returns the owning project ID.
func (client *Client) CurrentJob(ctx context.Context, jobToken string) (Job, error) {
	if jobToken == "" {
		return Job{}, errors.New("GitLab job token must not be empty")
	}

	jobClient, err := client.newAPIClient(jobToken, true)
	if err != nil {
		return Job{}, fmt.Errorf("create GitLab job-token client: %w", err)
	}

	started := time.Now()
	job, _, err := jobClient.Jobs.GetJobTokensJob(nil, gitlabapi.WithContext(ctx))
	if err != nil {
		apiErr := client.apiError("validate job token", err)
		client.observe("validate job token", started, apiErr)
		return Job{}, apiErr
	}

	if job == nil || job.Project == nil || job.Project.ID < 1 {
		apiErr := client.apiError("validate job token", errors.New("response does not include a valid project ID"))
		client.observe("validate job token", started, apiErr)
		return Job{}, apiErr
	}

	client.observe("validate job token", started, nil)
	return Job{ID: job.ID, Project: JobProject{ID: job.Project.ID}}, nil
}

// Project retrieves a project by numeric ID or URL-encoded path_with_namespace.
func (client *Client) Project(ctx context.Context, reference string) (Project, error) {
	if reference == "" || reference == "." || reference == ".." {
		return Project{}, errors.New("GitLab project reference must be a non-empty ID or path")
	}

	started := time.Now()
	project, _, err := client.api.Projects.GetProject(reference, nil, gitlabapi.WithContext(ctx))
	if err != nil {
		apiErr := client.apiError("get project", err)
		client.observe("get project", started, apiErr)
		return Project{}, apiErr
	}

	if project == nil {
		apiErr := client.apiError("get project", errors.New("response does not include a project"))
		client.observe("get project", started, apiErr)
		return Project{}, apiErr
	}

	client.observe("get project", started, nil)
	return Project{
		ID:                project.ID,
		Name:              project.Name,
		PathWithNamespace: project.PathWithNamespace,
		WebURL:            project.WebURL,
		Visibility:        string(project.Visibility),
	}, nil
}

// ProjectMembers lists all effective project members across every API page.
func (client *Client) ProjectMembers(ctx context.Context, projectID int64) ([]Member, error) {
	if projectID < 1 {
		return nil, errors.New("GitLab project ID must be positive")
	}

	members := make([]Member, 0)
	for page := int64(1); ; page++ {
		started := time.Now()
		pageMembers, response, err := client.api.ProjectMembers.ListAllProjectMembers(
			projectID,
			&gitlabapi.ListProjectMembersOptions{
				PerPage: apiPageSize,
				Page:    page,
			},
			gitlabapi.WithContext(ctx),
		)

		if err != nil {
			apiErr := client.apiError("list project members", err)
			client.observe("list project members", started, apiErr)
			return nil, apiErr
		}

		for _, member := range pageMembers {
			if member == nil {
				apiErr := client.apiError("list project members", errors.New("response contains a null member"))
				client.observe("list project members", started, apiErr)
				return nil, apiErr
			}

			members = append(members, Member{
				ID:          member.ID,
				Username:    member.Username,
				Name:        member.Name,
				State:       member.State,
				AccessLevel: int(member.AccessLevel),
			})
		}

		nextPage := int64(0)
		if response != nil && response.Header.Get("X-Next-Page") != "" {
			if response.NextPage <= page {
				apiErr := client.apiError("list project members", errors.New("invalid X-Next-Page header"))
				client.observe("list project members", started, apiErr)
				return nil, apiErr
			}

			nextPage = response.NextPage
		}
		client.observe("list project members", started, nil)

		if nextPage > 0 {
			page = nextPage - 1
			continue
		}

		if len(pageMembers) < apiPageSize {
			return members, nil
		}
	}
}

// User retrieves a GitLab user by numeric ID for legacy identity matching.
func (client *Client) User(ctx context.Context, userID int64) (User, error) {
	if userID < 1 {
		return User{}, errors.New("GitLab user ID must be positive")
	}

	started := time.Now()
	user, _, err := client.api.Users.GetUser(userID, nil, gitlabapi.WithContext(ctx))
	if err != nil {
		apiErr := client.apiError("get user", err)
		client.observe("get user", started, apiErr)
		return User{}, apiErr
	}

	if user == nil {
		apiErr := client.apiError("get user", errors.New("response does not include a user"))
		client.observe("get user", started, apiErr)
		return User{}, apiErr
	}

	client.observe("get user", started, nil)
	return User{
		ID:       user.ID,
		Username: user.Username,
		Name:     user.Name,
		Email:    user.Email,
	}, nil
}

// newAPIClient configures an SDK client with the shared HTTP policy.
func (client *Client) newAPIClient(token string, jobToken bool) (*gitlabapi.Client, error) {
	options := []gitlabapi.ClientOptionFunc{
		gitlabapi.WithBaseURL(client.baseURL.String()),
		gitlabapi.WithHTTPClient(client.http.HTTPClient()),
		gitlabapi.WithUserAgent(client.userAgent),
		gitlabapi.WithCustomRetryMax(apiRetries),
		gitlabapi.WithCustomRetryWaitMinMax(50*time.Millisecond, 100*time.Millisecond),
		gitlabapi.WithCustomRetry(retryRequest),
	}

	if jobToken {
		return gitlabapi.NewJobClient(token, options...)
	}

	return gitlabapi.NewClient(token, options...)
}

// retryRequest retries only canceled-safe reads on transient transport or API failures.
func retryRequest(ctx context.Context, response *http.Response, err error) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false, err
		}

		var networkError net.Error
		return errors.As(err, &networkError), nil
	}

	if response == nil {
		return false, nil
	}

	switch response.StatusCode {
	case http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true, nil

	default:
		return false, nil
	}
}

// observe records a GitLab SDK operation without storing request or response data.
func (client *Client) observe(operation string, started time.Time, err error) {
	client.observerMu.RLock()
	observer := client.observer
	logger := client.logger
	client.observerMu.RUnlock()
	statusClass := "2xx"
	status := 0
	result := "success"
	if err != nil {
		result = "error"
		statusClass = "error"
		if apiError, ok := errors.AsType[*httpclient.Error](err); ok && apiError.StatusCode != 0 {
			status = apiError.StatusCode
			statusClass = fmt.Sprintf("%dxx", apiError.StatusCode/100)
		}
	}
	duration := time.Since(started)
	if observer != nil {
		observer.ObserveRequest(upstream, operation, statusClass, duration)
	}

	if logger != nil {
		event := logger.Debug()
		if event.Enabled() {
			event.Str("component", "gitlab_api").
				Str("upstream", upstream).
				Str("operation", operation).
				Int("http_status", status).
				Dur("duration", duration).
				Str("result", result).
				Msg("GitLab API operation completed")
		}
	}
}

// apiError wraps SDK errors without exposing upstream response bodies.
func (client *Client) apiError(operation string, err error) error {
	if err == nil {
		return nil
	}

	if responseError, ok := errors.AsType[*gitlabapi.ErrorResponse](err); ok {
		return &httpclient.Error{
			Err:        err,
			Upstream:   upstream,
			Operation:  operation,
			StatusCode: responseError.StatusCode,
		}
	}

	return &httpclient.Error{
		Err:       err,
		Upstream:  upstream,
		Operation: operation,
	}
}
