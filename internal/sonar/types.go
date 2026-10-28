// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package sonar

import (
	"errors"
	"sync"

	"github.com/woozymasta/guassp/internal/httpclient"
)

const (
	apiPageSize  = 100
	userPageSize = 100
	upstream     = "sonarqube"
)

// ErrNotBound means that a SonarQube project has no ALM binding.
var ErrNotBound = errors.New("SonarQube project has no ALM binding")

// ErrInvalidRepositoryID indicates a GitLab ALM binding has an invalid ID.
var ErrInvalidRepositoryID = errors.New("invalid GitLab repository ID")

// ErrUnsupportedPermissionsAPI means the internal direct-permissions API
// returned an incompatible response or is unavailable.
var ErrUnsupportedPermissionsAPI = errors.New("unsupported Sonar permissions API")

// Client reads and updates SonarQube projects, users, and direct permissions.
type Client struct {
	http                      *httpclient.Client
	token                     string
	userManagementMu          sync.Mutex
	userManagementSupported   bool
	userManagementModeChecked bool
}

// Project contains the project fields used by Guassp.
type Project struct {
	// Key is the unique SonarQube project key.
	Key string `json:"key"`
	// Name is the display name shown in SonarQube.
	Name string `json:"name"`
	// Visibility is the project's current visibility.
	Visibility string `json:"visibility"`
}

// Binding describes a project's ALM binding.
type Binding struct {
	// Key is the configured ALM setting name.
	Key string
	// ALM identifies the source control provider.
	ALM string
	// Repository is the repository identifier returned by SonarQube.
	Repository string
	// URL is the ALM integration URL returned by SonarQube.
	URL string
	// ProjectID is the parsed GitLab project ID for GitLab bindings.
	ProjectID int64
	// Monorepo reports whether the binding uses monorepo mode.
	Monorepo bool
}

// User contains the identity and state fields used by Guassp.
type User struct {
	// ID is the internal SonarQube user identifier required by Web API v2.
	ID string `json:"id"`
	// Login is the SonarQube account login.
	Login string `json:"login"`
	// Name is the user's display name.
	Name string `json:"name"`
	// Email is the email visible to the API token.
	Email string `json:"email"`
	// ExternalProvider identifies the user's external identity provider.
	//nolint:tagliatelle // SonarQube defines this JSON field with camelCase.
	ExternalProvider string `json:"externalProvider"`
	// ExternalIdentity is the login at the external identity provider.
	//nolint:tagliatelle // SonarQube defines this JSON field with camelCase.
	ExternalIdentity string `json:"externalIdentity"`
	// Groups lists the groups assigned to the user.
	Groups []string `json:"groups"`
	// Active reports whether the account is active.
	Active bool `json:"active"`
}

// UserPermissions contains permissions assigned directly to one user.
type UserPermissions struct {
	// Login identifies the SonarQube user.
	Login string
	// Permissions contains only direct project permissions.
	Permissions []string
}

// pageInfo contains pagination metadata returned by SonarQube search APIs.
type pageInfo struct {
	// PageIndex is the one-based current page number.
	//nolint:tagliatelle // SonarQube defines this JSON field with camelCase.
	PageIndex int `json:"pageIndex"`
	// PageSize is the maximum number of entries in one page.
	//nolint:tagliatelle // SonarQube defines this JSON field with camelCase.
	PageSize int `json:"pageSize"`
	// Total is the number of matching entries across all pages.
	Total int `json:"total"`
}

// projectSearchResponse is the SonarQube project search response.
type projectSearchResponse struct {
	// Components contains projects returned for the current page.
	Components []Project `json:"components"`
	// Paging contains metadata for the current page.
	Paging pageInfo `json:"paging"`
}

// projectComponentResponse contains the requested project's current fields.
type projectComponentResponse struct {
	// Component contains the requested SonarQube project.
	Component Project `json:"component"`
}

// userSearchResponse is the SonarQube user search response.
type userSearchResponse struct {
	// Users contains users returned for the current page.
	Users []User `json:"users"`
	// Paging contains metadata for the current page.
	Paging pageInfo `json:"paging"`
}

// userManagementResponse is one page from the SonarQube Web API v2 user list.
type userManagementResponse struct {
	// Users contains users returned for the current page.
	Users []User `json:"users"`
	// Page contains pagination metadata when provided by the server.
	Page userManagementPageInfo `json:"page"`
}

// userManagementPageInfo contains Web API v2 pagination metadata.
type userManagementPageInfo struct {
	// Index is the one-based current page number.
	Index int `json:"index"`
	// Size is the number of entries in one page.
	Size int `json:"size"`
	// Total is the number of matching entries across all pages.
	Total int `json:"total"`
}

// bindingResponse contains the fields returned by the SonarQube ALM API.
type bindingResponse struct {
	// Key is the configured ALM setting name.
	Key string `json:"key"`
	// ALM identifies the source control provider.
	ALM string `json:"alm"`
	// Repository is the provider's repository identifier.
	Repository string `json:"repository"`
	// URL is the ALM integration URL.
	URL string `json:"url"`
	// Monorepo reports whether the binding uses monorepo mode.
	Monorepo bool `json:"monorepo"`
}
