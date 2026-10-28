// SPDX-License-Identifier: MIT
// Copyright (c) 2022-2026 WoozyMasta
// Source: github.com/woozymasta/guassp

package config

import (
	"github.com/woozymasta/guassp/internal/domain"
	"github.com/woozymasta/guassp/internal/logger"
)

// Config describes how Guassp connects to GitLab and SonarQube and keeps project access in sync.
// The GitLab and SonarQube sections provide the source and destination for synchronization.
// Other sections tune project discovery, permission and visibility policies, user handling,
// the HTTP service, and process logging.
// A section can be omitted when its default behavior suits the deployment.
type Config struct {

	// Permissions defines which SonarQube project permissions Guassp manages for each GitLab project access level.
	// Use it to adapt GitLab roles to the permissions enabled in SonarQube.
	// If omitted, Guassp uses its built-in role mapping.
	// Providing a mapping replaces that policy; a level with an empty list has no managed permissions.
	Permissions PermissionMapping `json:"permissions,omitempty" jsonschema_extras:"x-order=70"`

	// Visibility controls whether SonarQube project visibility follows the corresponding GitLab project.
	// This is useful when public and private projects must retain the same exposure after synchronization.
	// Set enabled to false to leave SonarQube visibility unchanged,
	// or provide a map to choose how each GitLab visibility is represented.
	Visibility VisibilityOptions `json:"visibility,omitzero" jsonschema:"omitempty" jsonschema_extras:"x-order=80"`

	// API controls authentication for the JSON API endpoints.
	// Configure a token to reject unauthenticated API requests before they can trigger upstream calls.
	API APIOptions `json:"api,omitzero" jsonschema:"omitempty" jsonschema_extras:"x-order=40"`

	// Web controls the browser pages and form-based manual project synchronization.
	// It can also protect these interactive operations with HTTP Basic authentication.
	Web WebOptions `json:"web,omitzero" jsonschema:"omitempty" jsonschema_extras:"x-order=50"`

	// SonarQube contains the destination server address and credentials used for API requests.
	// ALM and group settings further narrow which bindings or users are managed.
	SonarQube SonarQubeOptions `json:"sonarqube" jsonschema_extras:"x-order=30"`

	// Log controls the format, destination, and detail level of process logs.
	// Use debug or trace temporarily when investigating synchronization decisions or API behavior.
	Log logger.Options `json:"log,omitzero" jsonschema:"omitempty" jsonschema_extras:"x-order=110"`

	// Metrics controls whether Prometheus metrics are served and how that endpoint is protected.
	Metrics MetricsOptions `json:"metrics,omitzero" jsonschema:"omitempty" jsonschema_extras:"x-order=60"`

	// GitLab contains the source server address and credentials
	// used to discover projects, memberships, and user information.
	GitLab GitLabOptions `json:"gitlab" jsonschema_extras:"x-order=20"`

	// Users controls how GitLab members are matched to SonarQube users and whether accounts
	// known to be inactive in GitLab are deactivated in SonarQube.
	Users UserOptions `json:"users,omitzero" jsonschema:"omitempty" jsonschema_extras:"x-order=100"`

	// Discovery controls how a GitLab project is associated with a SonarQube project
	// and when Guassp refreshes its view of all GitLab-bound projects.
	Discovery DiscoveryOptions `json:"discovery,omitzero" jsonschema:"omitempty" jsonschema_extras:"x-order=90"`

	// Runtime controls the HTTP listener and the number of projects reconciled concurrently.
	Runtime RuntimeOptions `json:"runtime,omitzero" jsonschema:"omitempty" jsonschema_extras:"x-order=10"`

	// Compat enables the alternate request format supported for CI synchronization.
	// Leave this section unset when clients send the job token in the request header.
	Compat CompatibilityOptions `json:"compat,omitzero" jsonschema:"omitempty" jsonschema_extras:"x-order=120"`
}

// GitLabOptions configures the GitLab instance used as the source of projects, memberships, and user identities.
type GitLabOptions struct {
	// URL is the address of the GitLab instance.
	// Include any path prefix used by a self-managed installation so API requests reach the correct instance.
	URL string `json:"url" jsonschema:"minLength=1,format=uri,pattern=^https?://,example=https://gitlab.example.com" jsonschema_extras:"x-order=10"`

	// Token authenticates Guassp's GitLab API requests.
	// Use the read_api scope and grant its account access to every bound project and its effective member list.
	// The scope permits API reads; account access determines which projects and memberships are visible.
	// This service credential is separate from CI job tokens used for individual sync requests.
	Token string `json:"token" jsonschema:"minLength=1,writeOnly=true,example=${GITLAB_TOKEN:?set GITLAB_TOKEN}" jsonschema_extras:"x-order=20"`

	// SkipUsers lists GitLab user IDs whose access Guassp must not manage.
	// Use this to preserve manually maintained SonarQube access for selected accounts.
	SkipUsers []int64 `json:"skip_users,omitempty" jsonschema:"minimum=1" jsonschema_extras:"x-order=30"`
}

// SonarQubeOptions configures the SonarQube instance where project access and visibility are reconciled.
type SonarQubeOptions struct {
	// URL is the address of the SonarQube instance.
	// Include its context path when the server is hosted below a URL prefix.
	URL string `json:"url" jsonschema:"minLength=1,format=uri,pattern=^https?://,example=https://sonar.example.com" jsonschema_extras:"x-order=10"`

	// Token authenticates Guassp's SonarQube Web API requests and must be a user token.
	// Current project discovery and user directory API calls require global Administer System permission.
	// User deactivation also requires this permission and affects the entire SonarQube instance.
	Token string `json:"token" jsonschema:"minLength=1,writeOnly=true,example=${SONARQUBE_TOKEN:?set SONARQUBE_TOKEN}" jsonschema_extras:"x-order=20"`

	// ALMKey selects the GitLab ALM configuration whose project bindings Guassp should use
	// when SonarQube has more than one GitLab configuration.
	// Leave it empty to use the available binding without an additional ALM filter.
	ALMKey string `json:"alm_key,omitempty" jsonschema:"example=gitlab" jsonschema_extras:"x-order=30"`

	// SkipGroups names SonarQube groups whose members Guassp should leave untouched.
	// A user in any listed group is excluded from direct permission reconciliation,
	// which helps preserve access managed through local or privileged groups.
	SkipGroups []string `json:"skip_groups,omitempty" jsonschema:"minLength=1,pattern=[^[:space:]]" jsonschema_extras:"x-order=40"`
}

// RuntimeOptions configures the network endpoint and concurrency of the running service.
type RuntimeOptions struct {
	// Listen is the local address where Guassp accepts HTTP connections for its API,
	// health probes, optional metrics, and enabled web interface.
	Listen string `json:"listen,omitempty" jsonschema:"default=:8080" jsonschema_extras:"x-order=10"`

	// Workers controls how many project synchronizations can run at the same time.
	// Increase it when the service needs to process a large queue faster;
	// keep it modest to limit concurrent load on GitLab and SonarQube.
	Workers int `json:"workers" jsonschema:"minimum=1,default=4" jsonschema_extras:"x-order=20"`

	// RunHistory sets how many completed project synchronizations remain available in memory.
	// Increase it to keep more recent runs on the status page and run-history API.
	RunHistory int `json:"run_history,omitempty" jsonschema:"minimum=1,maximum=4096,default=256" jsonschema_extras:"x-order=30"`
}

// PermissionMapping associates exact numeric GitLab project access levels with SonarQube project permissions.
// If omitted, Guassp uses a cumulative built-in mapping for access levels 10, 20, 30, 40, and 50.
// A custom mapping replaces the built-in mapping. Unlisted access levels are left untouched.
// Permissions named anywhere in the active mapping are managed; other permission types are left untouched.
// An explicitly empty list assigns no managed permissions to that access level.
type PermissionMapping map[string][]string

// VisibilityOptions controls whether and how GitLab project visibility is reflected in SonarQube.
// By default public maps to public, while internal and private map to private.
// A custom map replaces the built-in mapping; disable Enabled to preserve SonarQube visibility as-is.
type VisibilityOptions struct {
	// Map translates GitLab public, internal, and private visibility into SonarQube public or private visibility.
	// A custom map replaces the built-in mapping, so include each GitLab visibility that can occur.
	// If omitted, the built-in mapping is used.
	Map map[domain.GitLabVisibility]domain.SonarVisibility `json:"map,omitempty" jsonschema_extras:"x-order=20"`

	// Enabled turns visibility reconciliation on or off.
	// When disabled, Guassp does not change the existing SonarQube project visibility.
	Enabled bool `json:"enabled,omitempty" jsonschema:"default=true" jsonschema_extras:"x-order=10"`
}

// UserOptions controls how project members are associated with SonarQube accounts
// and whether GitLab account state can trigger SonarQube deactivation.
type UserOptions struct {
	// Match selects the identity used to find a SonarQube account for each GitLab member.
	// The external mode is intended for accounts linked to GitLab in SonarQube.
	// Choose email or name when your SonarQube accounts are identified by those attributes.
	Match domain.UserMatchMode `json:"match,omitempty" jsonschema:"enum=external,enum=email,enum=name,default=external" jsonschema_extras:"x-order=10"`

	// Deactivation allows Guassp to deactivate a matched SonarQube account
	// when GitLab reports the corresponding user in a known inactive state.
	// This applies to the account itself, rather than removing access only from the current project.
	Deactivation bool `json:"deactivation,omitempty" jsonschema_extras:"x-order=20"`
}

// APIOptions controls authentication for JSON API endpoints.
type APIOptions struct {
	// Token requires this bearer token on every /api/* request.
	// On CI synchronization, also send the GitLab job token in the JOB-TOKEN header.
	// Leave it empty to keep the API token check disabled.
	Token string `json:"token,omitempty" jsonschema:"writeOnly=true,example=${GUASSP_API_TOKEN:-}" jsonschema_extras:"x-order=10"`
}

// DiscoveryOptions controls how Guassp finds the SonarQube project for a GitLab project
// and refreshes the set of projects to synchronize.
type DiscoveryOptions struct {
	// FullSyncAt schedules a daily refresh of GitLab-bound SonarQube projects at local service time.
	// Leave it empty to turn off scheduled full discovery cycles.
	FullSyncAt DailyTime `json:"full_sync_at,omitempty" jsonschema:"default=03:00,pattern=^([01][0-9]|2[0-3]):[0-5][0-9]$|^$" jsonschema_extras:"x-order=10"`

	// ManualFullSync enables POST /api/v1/full-sync and its button in the web console.
	// The API uses api.token and the button follows the web Basic authentication settings.
	// Leave it disabled when users must not trigger a full sync.
	ManualFullSync bool `json:"manual_full_sync,omitempty" jsonschema_extras:"x-order=20"`

	// PathFallback lets Guassp look for a SonarQube project
	// with the same full GitLab path when no usable ALM binding identifies one.
	// It is intended for installations where project bindings are missing; ambiguous matches are not selected.
	PathFallback bool `json:"path_fallback,omitempty" jsonschema_extras:"x-order=20"`
}

// WebOptions controls the browser interface and form-based manual synchronization.
type WebOptions struct {
	// BasePath is the public URL path prefix used when GUASSP is published below a reverse-proxy path.
	// The service accepts requests both with and without this prefix; leave it empty when served at the host root.
	BasePath string `json:"base_path,omitempty" jsonschema:"pattern=^$|^(/[A-Za-z0-9_-]+)+$,default=" jsonschema_extras:"x-order=20"`

	// Username is the account name for HTTP Basic authentication
	// on the browser interface and form-based manual synchronization.
	// Set it together with Password to protect those operations.
	Username string `json:"username,omitempty" jsonschema:"example=operator" jsonschema_extras:"x-order=30"`

	// Password is the credential paired with Username for HTTP Basic authentication.
	// Keep it in a secret store or environment-specific configuration rather than a checked-in example file.
	Password string `json:"password,omitempty" jsonschema:"writeOnly=true,example=${WEB_PASSWORD:?set WEB_PASSWORD}" jsonschema_extras:"x-order=40"`

	// SyncRate limits how frequently a client can request a manual project sync.
	// Use it to prevent accidental or abusive repeated requests to the upstream services;
	// set it to zero when another layer already provides the required request control.
	SyncRate string `json:"sync_rate,omitempty" jsonschema:"pattern=^(0|[0-9]*[1-9][0-9]*/[smh])$,default=10/m" jsonschema_extras:"x-order=50"`

	// Enabled serves the rendered pages and enables the manual synchronization interface.
	// Disabling it removes those interactive features while leaving the service API and operational endpoints available.
	Enabled bool `json:"enabled,omitempty" jsonschema:"default=true" jsonschema_extras:"x-order=10"`
}

// MetricsOptions controls the Prometheus endpoint and its optional authentication.
type MetricsOptions struct {
	// Token requires this bearer token when a client requests /metrics.
	// Leave it empty to disable token authentication; do not combine it with Basic credentials.
	Token string `json:"token,omitempty" jsonschema:"writeOnly=true,example=${METRICS_TOKEN:-}" jsonschema_extras:"x-order=30"`

	// Username enables HTTP Basic authentication for /metrics when paired with Password.
	// Do not combine Basic credentials with Token.
	Username string `json:"username,omitempty" jsonschema:"example=${METRICS_USERNAME:-}" jsonschema_extras:"x-order=40"`

	// Password is the HTTP Basic password paired with Username.
	Password string `json:"password,omitempty" jsonschema:"writeOnly=true,example=${METRICS_PASSWORD:-}" jsonschema_extras:"x-order=50"`

	// Enabled serves the Prometheus metrics endpoint at /metrics.
	// Disable it when metrics are collected through another path or should not be exposed.
	Enabled bool `json:"enabled,omitempty" jsonschema:"default=true" jsonschema_extras:"x-order=10"`

	// IncludeRuntime adds Go runtime and operating-system process metrics to /metrics.
	// Enable it for runtime diagnostics such as goroutine count, memory use, and process CPU time.
	IncludeRuntime bool `json:"include_runtime,omitempty" jsonschema_extras:"x-order=20"`
}

// CompatibilityOptions enables an alternate request format for CI synchronization.
type CompatibilityOptions struct {
	// JobTokenBody allows the CI synchronization endpoint to read a job token from the JSON request body.
	// Enable it when a client cannot send the token in the request header.
	JobTokenBody bool `json:"job_token_body,omitempty" jsonschema_extras:"x-order=10"`
}
