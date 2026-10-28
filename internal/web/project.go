// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package web

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/woozymasta/guassp/internal/gitlab"
)

var (
	errInvalidProjectResponse = errors.New("GitLab returned an invalid project")
	errProjectLookup          = errors.New("GitLab project lookup failed")
)

// ProjectLookup resolves a GitLab project reference through the configured API.
type ProjectLookup interface {
	// Project returns the GitLab project identified by an API reference.
	Project(context.Context, string) (gitlab.Project, error)
}

// projectResolver parses user input locally and resolves it only through GitLab.
type projectResolver struct {
	lookup  ProjectLookup
	baseURL *url.URL
}

// newProjectResolver creates a resolver bound to the configured GitLab URL.
func newProjectResolver(lookup ProjectLookup, baseURL *url.URL) (*projectResolver, error) {
	if lookup == nil || baseURL == nil || baseURL.Host == "" || baseURL.Scheme == "" {
		return nil, errors.New("GitLab project lookup and base URL are required")
	}

	return &projectResolver{lookup: lookup, baseURL: baseURL}, nil
}

// Resolve accepts a numeric ID, namespace path, or canonical GitLab project URL.
func (resolver *projectResolver) Resolve(ctx context.Context, input string) (gitlab.Project, error) {
	reference, err := resolver.reference(input)
	if err != nil {
		return gitlab.Project{}, err
	}

	project, err := resolver.lookup.Project(ctx, reference)
	if err != nil {
		return gitlab.Project{}, errors.Join(errProjectLookup, err)
	}
	if project.ID < 1 || strings.TrimSpace(project.PathWithNamespace) == "" {
		return gitlab.Project{}, errInvalidProjectResponse
	}

	return project, nil
}

// reference converts accepted input to a GitLab API project identifier.
func (resolver *projectResolver) reference(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" || strings.HasPrefix(input, "//") || strings.ContainsAny(input, "\\?#") ||
		strings.ContainsRune(input, '\x00') {
		return "", errors.New("project must be an ID, path, or canonical GitLab URL")
	}
	if isDecimal(input) {
		projectID, err := strconv.ParseInt(input, 10, 64)
		if err != nil || projectID < 1 {
			return "", errors.New("project ID must be positive")
		}
		return strconv.FormatInt(projectID, 10), nil
	}

	if strings.Contains(input, "://") || strings.HasPrefix(strings.ToLower(input), "http:") ||
		strings.HasPrefix(strings.ToLower(input), "https:") {
		return resolver.urlReference(input)
	}

	return validateProjectPath(input)
}

// urlReference validates a pasted URL without making a request to its host.
func (resolver *projectResolver) urlReference(input string) (string, error) {
	parsed, err := url.Parse(input)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return "", errors.New("project URL is malformed")
	}
	if !strings.EqualFold(parsed.Scheme, resolver.baseURL.Scheme) ||
		!sameHost(parsed, resolver.baseURL) {
		return "", errors.New("project URL must use the configured GitLab origin")
	}

	projectPath := strings.TrimPrefix(parsed.Path, "/")
	basePath := strings.Trim(resolver.baseURL.Path, "/")
	if basePath != "" {
		if projectPath == basePath {
			return "", errors.New("project URL must include a project path")
		}
		prefix := basePath + "/"
		if !strings.HasPrefix(projectPath, prefix) {
			return "", errors.New("project URL is outside the configured GitLab path")
		}
		projectPath = strings.TrimPrefix(projectPath, prefix)
	}

	return validateProjectPath(projectPath)
}

// validateProjectPath rejects ambiguous and traversal-like project references.
func validateProjectPath(path string) (string, error) {
	path = strings.Trim(path, "/")
	if path == "" {
		return "", errors.New("project path must not be empty")
	}
	for component := range strings.SplitSeq(path, "/") {
		if component == "" || component == "." || component == ".." ||
			strings.TrimSpace(component) != component || strings.IndexFunc(component, unicode.IsControl) >= 0 {
			return "", errors.New("project path contains an invalid component")
		}
	}

	return path, nil
}

// isDecimal reports whether value contains only ASCII decimal digits.
func isDecimal(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}

	return value != ""
}

// sameHost compares DNS names case-insensitively and resolves default ports.
func sameHost(first, second *url.URL) bool {
	return strings.EqualFold(first.Hostname(), second.Hostname()) && effectivePort(first) == effectivePort(second)
}

// effectivePort returns the explicit port or the scheme's standard port.
func effectivePort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	if strings.EqualFold(value.Scheme, "https") {
		return "443"
	}
	if strings.EqualFold(value.Scheme, "http") {
		return "80"
	}

	return ""
}
