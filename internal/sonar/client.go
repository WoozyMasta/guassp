// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

// Package sonar provides a typed client for the SonarQube Web API endpoints
// used by Guassp.
package sonar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"github.com/woozymasta/guassp/internal/httpclient"
)

// New creates a SonarQube client for a parsed base URL and user token.
func New(baseURL *url.URL, token, userAgent string) (*Client, error) {
	if token == "" {
		return nil, errors.New("SonarQube token must not be empty")
	}

	httpClient, err := httpclient.New(baseURL, userAgent)
	if err != nil {
		return nil, fmt.Errorf("create SonarQube HTTP client: %w", err)
	}

	return &Client{http: httpClient, token: token}, nil
}

// SetObserver configures the shared HTTP client's optional request observer.
func (client *Client) SetObserver(observer httpclient.RequestObserver) {
	client.http.SetObserver(observer)
}

// SetLogger configures safe structured logging for SonarQube requests.
func (client *Client) SetLogger(logger zerolog.Logger) {
	client.http.SetLogger(logger)
}

// Preflight verifies project search and project read access.
func (client *Client) Preflight(ctx context.Context) error {
	requestURL := client.http.Endpoint("api", "projects", "search")
	query := requestURL.Query()
	query.Set("p", "1")
	query.Set("ps", "1")
	requestURL.RawQuery = query.Encode()

	var result projectSearchResponse
	if err := client.getJSON(ctx, requestURL, "preflight project search", &result); err != nil {
		return fmt.Errorf("verify SonarQube project search access: %w", err)
	}
	if len(result.Components) == 0 {
		return nil
	}
	if _, err := client.ProjectVisibility(ctx, result.Components[0].Key); err != nil {
		return fmt.Errorf("verify SonarQube project read access: %w", err)
	}

	return nil
}

// Version returns the SonarQube server version string.
func (client *Client) Version(ctx context.Context) (string, error) {
	response, err := client.get(
		ctx,
		client.http.Endpoint("api", "server", "version"),
		"get server version",
	)
	if err != nil {
		return "", err
	}
	defer func() { _ = response.Body.Close() }()

	data, err := httpclient.ReadBody(response.Body)
	if err != nil {
		return "", &httpclient.Error{
			Upstream:  upstream,
			Operation: "get server version",
			Err:       err,
		}
	}

	version := strings.TrimSpace(string(data))
	if version == "" {
		return "", &httpclient.Error{
			Upstream:  upstream,
			Operation: "get server version",
			Err:       errors.New("empty version response"),
		}
	}

	return version, nil
}

// Projects lists all SonarQube projects.
func (client *Client) Projects(ctx context.Context) ([]Project, error) {
	projects := make([]Project, 0)
	for page := 1; ; page++ {
		requestURL := client.http.Endpoint("api", "projects", "search")
		query := requestURL.Query()
		query.Set("p", strconv.Itoa(page))
		query.Set("ps", strconv.Itoa(apiPageSize))
		requestURL.RawQuery = query.Encode()

		var result projectSearchResponse
		if err := client.getJSON(ctx, requestURL, "search projects", &result); err != nil {
			return nil, err
		}

		projects = append(projects, result.Components...)
		if !hasNextPage(result.Paging, len(result.Components), page) {
			return projects, nil
		}
	}
}

// ProjectVisibility returns the current visibility for one SonarQube project.
func (client *Client) ProjectVisibility(ctx context.Context, projectKey string) (string, error) {
	if projectKey == "" {
		return "", errors.New("SonarQube project key must not be empty")
	}

	requestURL := client.http.Endpoint("api", "components", "show")
	query := requestURL.Query()
	query.Set("component", projectKey)
	requestURL.RawQuery = query.Encode()

	var response projectComponentResponse
	if err := client.getJSON(ctx, requestURL, "get project visibility", &response); err != nil {
		return "", err
	}

	if response.Component.Key != projectKey {
		return "", &httpclient.Error{
			Upstream:  upstream,
			Operation: "get project visibility",
			Err:       errors.New("response project key does not match request"),
		}
	}
	if response.Component.Visibility != "public" && response.Component.Visibility != "private" {
		return "", &httpclient.Error{
			Upstream:  upstream,
			Operation: "get project visibility",
			Err:       errors.New("response has an unsupported visibility"),
		}
	}

	return response.Component.Visibility, nil
}

// Binding retrieves a project's ALM binding.
// A GitLab repository identifier is parsed as a positive decimal project ID when the binding uses GitLab.
func (client *Client) Binding(ctx context.Context, projectKey string) (Binding, error) {
	if projectKey == "" {
		return Binding{}, errors.New("SonarQube project key must not be empty")
	}

	requestURL := client.http.Endpoint("api", "alm_settings", "get_binding")
	query := requestURL.Query()
	query.Set("project", projectKey)
	requestURL.RawQuery = query.Encode()

	var response bindingResponse
	if err := client.getJSON(
		ctx,
		requestURL,
		"get ALM binding",
		&response,
	); err != nil {
		var apiError *httpclient.Error
		if errors.As(err, &apiError) && apiError.StatusCode == http.StatusNotFound {
			return Binding{}, ErrNotBound
		}

		return Binding{}, err
	}

	binding := Binding{
		Key:        response.Key,
		ALM:        response.ALM,
		Repository: response.Repository,
		URL:        response.URL,
		Monorepo:   response.Monorepo,
	}

	if binding.ALM == "gitlab" {
		projectID, err := strconv.ParseInt(binding.Repository, 10, 64)
		if err != nil || projectID < 1 {
			return binding, &httpclient.Error{
				Upstream:  upstream,
				Operation: "get ALM binding",
				Err:       fmt.Errorf("%w: value is not a positive decimal integer", ErrInvalidRepositoryID),
			}
		}

		binding.ProjectID = projectID
	}

	return binding, nil
}

// Users lists all SonarQube users.
func (client *Client) Users(ctx context.Context) ([]User, error) {
	supported, err := client.supportsUserManagementV2(ctx)
	if err != nil {
		return nil, err
	}
	if supported {
		return client.userManagementUsers(ctx)
	}

	users := make([]User, 0)
	for page := 1; ; page++ {
		requestURL := client.http.Endpoint("api", "users", "search")
		query := requestURL.Query()
		query.Set("p", strconv.Itoa(page))
		query.Set("ps", strconv.Itoa(apiPageSize))
		requestURL.RawQuery = query.Encode()

		var result userSearchResponse
		if err := client.getJSON(ctx, requestURL, "search users", &result); err != nil {
			return nil, err
		}

		users = append(users, result.Users...)
		if !hasNextPage(result.Paging, len(result.Users), page) {
			break
		}
	}

	return users, nil
}

// SearchProjects searches projects by a query for legacy binding fallback.
func (client *Client) SearchProjects(ctx context.Context, queryValue string) ([]Project, error) {
	projects := make([]Project, 0)
	for page := 1; ; page++ {
		requestURL := client.http.Endpoint("api", "projects", "search")
		query := requestURL.Query()
		query.Set("q", queryValue)
		query.Set("p", strconv.Itoa(page))
		query.Set("ps", strconv.Itoa(apiPageSize))
		requestURL.RawQuery = query.Encode()

		var result projectSearchResponse
		if err := client.getJSON(
			ctx,
			requestURL,
			"search projects by query",
			&result,
		); err != nil {
			return nil, err
		}

		projects = append(projects, result.Components...)
		if !hasNextPage(result.Paging, len(result.Components), page) {
			return projects, nil
		}
	}
}

// GrantUserPermission assigns a direct project permission to a user.
func (client *Client) GrantUserPermission(ctx context.Context, login, permission, projectKey string) error {
	return client.permissionChange(ctx, "add_user", login, permission, projectKey, "grant user permission")
}

// RevokeUserPermission removes a direct project permission from a user.
func (client *Client) RevokeUserPermission(ctx context.Context, login, permission, projectKey string) error {
	return client.permissionChange(ctx, "remove_user", login, permission, projectKey, "revoke user permission")
}

// UpdateProjectVisibility changes a project's visibility.
func (client *Client) UpdateProjectVisibility(ctx context.Context, projectKey, visibility string) error {
	if visibility != "public" && visibility != "private" {
		return errors.New("SonarQube visibility must be public or private")
	}
	if projectKey == "" {
		return errors.New("SonarQube project key must not be empty")
	}

	return client.postForm(ctx, "update project visibility", url.Values{
		"project":    {projectKey},
		"visibility": {visibility},
	}, "api", "projects", "update_visibility")
}

// DeactivateUser deactivates a SonarQube user.
func (client *Client) DeactivateUser(ctx context.Context, user User) error {
	supported, err := client.supportsUserManagementV2(ctx)
	if err != nil {
		return err
	}
	if supported {
		if user.ID == "" {
			return errors.New("SonarQube user ID is required for Web API v2 deactivation")
		}

		return client.delete(ctx, "deactivate user", "api", "v2", "users-management", "users", user.ID)
	}
	if user.Login == "" {
		return errors.New("SonarQube user login must not be empty")
	}

	return client.postForm(
		ctx,
		"deactivate user",
		url.Values{"login": {user.Login}},
		"api",
		"users",
		"deactivate",
	)
}

// permissionChange grants or revokes a user's direct project permission.
func (client *Client) permissionChange(
	ctx context.Context,
	action, login, permission, projectKey, operation string,
) error {
	return client.postForm(ctx, operation, url.Values{
		"login":      {login},
		"permission": {permission},
		"projectKey": {projectKey},
	}, "api", "permissions", action)
}

// postForm sends one authenticated form request to SonarQube.
func (client *Client) postForm(ctx context.Context, operation string, values url.Values, pathSegments ...string) error {
	requestURL := client.http.Endpoint(pathSegments...)
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		requestURL.String(),
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		return &httpclient.Error{
			Upstream:  upstream,
			Operation: operation,
			Err:       err,
		}
	}

	request.Header = client.authHeaders()
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.http.Do(request, upstream, operation)
	if err != nil {
		return err
	}

	return closeResponse(response)
}

// delete sends one authenticated DELETE request to SonarQube.
func (client *Client) delete(ctx context.Context, operation string, pathSegments ...string) error {
	requestURL := client.http.Endpoint(pathSegments...)
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, requestURL.String(), nil)
	if err != nil {
		return &httpclient.Error{
			Upstream:  upstream,
			Operation: operation,
			Err:       err,
		}
	}

	request.Header = client.authHeaders()
	response, err := client.http.Do(request, upstream, operation)
	if err != nil {
		return err
	}

	return closeResponse(response)
}

// get sends one authenticated GET request to SonarQube.
func (client *Client) get(ctx context.Context, requestURL *url.URL, operation string) (*http.Response, error) {
	return client.http.Get(ctx, requestURL, client.authHeaders(), upstream, operation)
}

// getJSON decodes one authenticated JSON response from SonarQube.
func (client *Client) getJSON(ctx context.Context, requestURL *url.URL, operation string, destination any) error {
	response, err := client.get(ctx, requestURL, operation)
	if err != nil {
		return err
	}

	defer func() { _ = response.Body.Close() }()
	if err := httpclient.DecodeJSON(response.Body, destination); err != nil {
		return &httpclient.Error{
			Upstream:  upstream,
			Operation: operation,
			Err:       err,
		}
	}

	return nil
}

// authHeaders returns headers for an authenticated SonarQube request.
func (client *Client) authHeaders() http.Header {
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+client.token)
	return headers
}

// closeResponse drains a small response body before closing it.
func closeResponse(response *http.Response) error {
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<10))
	closeErr := response.Body.Close()
	if readErr != nil {
		return &httpclient.Error{
			Upstream:  upstream,
			Operation: "read response",
			Err:       readErr,
		}
	}

	if closeErr != nil {
		return &httpclient.Error{
			Upstream:  upstream,
			Operation: "close response",
			Err:       closeErr,
		}
	}

	return nil
}

// hasNextPage reports whether another page is available from search metadata.
func hasNextPage(paging pageInfo, count, page int) bool {
	if paging.Total > 0 && paging.PageSize > 0 {
		return paging.PageIndex*paging.PageSize < paging.Total
	}

	return count == apiPageSize && page > 0
}
