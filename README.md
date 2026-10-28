# GUASSP

**GUASSP** stands for
**G**itLab **U**ser **A**ccess **S**ynchronization
for **S**onarQube **P**rojects.
It reconciles access to SonarQube projects
from GitLab project membership and visibility.

![GitLab access levels mapped to SonarQube permissions][permissions scheme]

## Installation

### Container images

Release images are published to both registries:

```text
ghcr.io/woozymasta/guassp:latest
docker.io/woozymasta/guassp:latest
```

### Release binaries

Download the latest binary for your operating system and architecture:

**Architecture** | **macOS**       | **Linux**       | **Windows**
---------------- | --------------- | --------------- | ----------------
**AMD64**        | [macOS amd64][] | [Linux amd64][] | [Windows amd64][]
**ARM64**        | [macOS arm64][] | [Linux arm64][] | [Windows arm64][]

For Linux AMD64, install the binary with:

```sh
curl -sSfLo guassp \
  https://github.com/WoozyMasta/guassp/releases/latest/download/guassp-linux-amd64
sudo install -m 0755 guassp /usr/local/bin/guassp
rm guassp
guassp -v
```

For systemd installation,
see the [systemd setup guide](./deploy/systemd/README.md).

## Start

1. Copy the [example configuration][config example] to `guassp.yaml`.
2. Set the GitLab and SonarQube URLs and service tokens.
3. Run `go run ./cmd/guassp` or build with `go build ./cmd/guassp`.

With no arguments, GUASSP reads `./guassp.yaml`;
it fails if the file is missing.
Set `GUASSP_CONFIG_PATH` to select the file through the environment instead.
An explicit path argument takes precedence over this variable.
Pass a config path explicitly to create an example
at that path when the file is missing or empty.
Edit the generated file before starting the service.

GUASSP loads `.env` from the working directory before reading the config.
Variables already present in the process environment are kept.
Do not commit `.env`; it is git-ignored.

Configuration can be YAML or JSON.
See the [configuration reference][config]
and [Kubernetes deployment notes][kustomize].

Environment variables are expanded in configuration values,
including inside strings; mapping keys are not expanded:

```yaml
gitlab:
  token: ${GITLAB_TOKEN:?set GITLAB_TOKEN}
sonarqube:
  token: ${SONARQUBE_TOKEN:?set SONARQUBE_TOKEN}
web:
  password: ${WEB_PASSWORD:-}
```

* `${VAR}` becomes an empty string when unset.
* `${VAR:-default}` uses a fallback without changing the environment.
* `${VAR:=default}` uses a fallback and sets the environment variable.
* `${VAR:?message}` fails config loading when the variable is unset or empty.
* `$${VAR}` preserves the literal `${VAR}`.

In JSON, quote expressions containing `:`, for example
`"${GITLAB_TOKEN:?set GITLAB_TOKEN}"`.

## Synchronization

Configure GitLab as an ALM integration in SonarQube
and bind each SonarQube project to its GitLab project.
GUASSP uses the binding's GitLab project ID;
one GitLab project can be bound to multiple SonarQube projects.
Set `sonarqube.alm_key` when bound projects
use multiple GitLab ALM setting keys.
Without it, discovery fails if it finds bindings from more than one setting.

The CI sync endpoint validates the GitLab job token
and uses its job record to identify the source project.
A manual request resolves a GitLab project ID, full namespace path,
or canonical URL on the configured GitLab host.
GUASSP then reads that project's effective membership, matches members
to SonarQube accounts, and reconciles each bound SonarQube project.
The request only queues the work;
the caller does not wait for reconciliation to finish.

For each eligible matched user, GUASSP changes only direct SonarQube project
permissions named in the active `permissions` map.
SonarQube group grants and permission types outside that map are left alone.
GitLab group membership is included through the user's effective project role;
GUASSP does not change GitLab membership
or synchronize SonarQube group permissions.
Changing a mapped role adjusts managed direct grants;
removing a user from effective membership removes those grants.
Unmatched and ambiguous identities are left untouched.

By default, `discovery.full_sync_at` is `03:00` local service time.
GUASSP checks upstream access at startup, then discovers all GitLab-bound
SonarQube projects and queues their GitLab projects only at the configured time.
Set it to an empty string to disable scheduled discovery;
the first CI or manual request then loads the binding index on demand.
Startup never triggers a full discovery cycle.
Missed schedule times are not replayed after downtime.
Set `discovery.manual_full_sync: true` to expose `POST /api/v1/full-sync`
and the full-sync button in the web console.
`/readyz` remains unavailable until startup preflight passes.
Failed preflight is retried every 30 seconds.
Preflight checks GitLab token identity
and one membership-filtered project-list request,
then SonarQube project search and read access to one result when available.
It does not test every GitLab member list,
SonarQube binding, or permission write.
CI and manual sync requests are rejected until preflight passes.

`runtime.workers` sets the number of concurrent project reconciliations.
`runtime.run_history` sets how many completed runs are kept in memory; it
defaults to 256 and accepts values from 1 to 4096. The queue, binding index,
run history, rate-limit state, and metrics are in memory and are lost when the
process stops.

## GitLab CI

Run the scan against the SonarQube project already bound
to the current GitLab project.
Set `SONAR_PROJECT_KEY`, `SONARQUBE_URL`, `SONARQUBE_ANALYSIS_TOKEN`,
and `GUASSP_URL` as CI/CD variables.
If GUASSP has `api.token` configured, also set `GUASSP_API_TOKEN`.
Mask secret variables and protect them when the job runs only on protected refs.
The scanner image must provide `sonar-scanner` and `curl`.
This example assumes `api.token` is set.

```yaml
sonarqube:
  stage: test
  variables:
    SONAR_HOST_URL: "$SONARQUBE_URL"
    SONAR_TOKEN: "$SONARQUBE_ANALYSIS_TOKEN"
  script:
    - sonar-scanner -Dsonar.projectKey="$SONAR_PROJECT_KEY"
    - >-
      curl --fail --silent --show-error --request POST
      --header "Authorization: Bearer $GUASSP_API_TOKEN"
      --header "JOB-TOKEN: $CI_JOB_TOKEN"
      "$GUASSP_URL/api/v1/sync"
```

With `api.token`, `Authorization` carries the GUASSP API token
and `JOB-TOKEN` carries `CI_JOB_TOKEN`.
Without `api.token`, omit `JOB-TOKEN`
and send the job token as `Authorization: Bearer $CI_JOB_TOKEN`.
GitLab validates the job token before GUASSP queues the project.

The scanner token and `sonarqube.token` are different credentials.
Use a SonarQube project analysis token for scanning;
GUASSP uses its own SonarQube user token for management API calls.

## Service credentials

* **GitLab:**
  Create `gitlab.token` with the `read_api` scope.
  The scope allows read-only API requests;
  the token account must also be able to read every GitLab project
  bound to an in-scope SonarQube project and its effective member list;
  `read_api` alone does not grant project access.
  GitLab's [`members/all` endpoint][gitlab member API] returns memberships
  visible to that account, including inherited project roles.
  The returned `access_level` is each user's effective role on that project;
  GUASSP does not enumerate unrelated group memberships.
  A group access token is suitable only if its scope covers all bound projects;
  use a service-account PAT for projects across unrelated groups.
  A project access token covers one project,
  and deploy tokens cannot authenticate to the REST API.
  GUASSP needs no GitLab write scope.
* **SonarQube:** `sonarqube.token` must be a user token
  with global `Administer System` permission for the current project discovery
  and user directory API calls. This grants full control of the instance.
  Use a dedicated account and keep this token in a secret store.
  Project and global analysis tokens are for scanning,
  not GUASSP's management calls.

See GitLab's [token types][gitlab tokens],
[token scopes][token scopes], and [CI job tokens][job tokens],
and SonarQube's [token types][sonar tokens]
and [permissions][sonar permissions].

## Policies

### User matching and exclusions

All match modes require a SonarQube account linked to GitLab:
its external provider must be `gitlab` and its external identity
must equal the GitLab username or numeric user ID.
`users.match: external` uses that link alone;
`email` and `name` additionally require the corresponding email
or display name to match.
They do not match unrelated SonarQube accounts by email or name.
Email matching makes an additional GitLab user API request
and depends on the email GitLab exposes to the service account.
A user is not synchronized when the match is missing or ambiguous.

`gitlab.skip_users` excludes listed GitLab user IDs
from direct permission changes.
`sonarqube.skip_groups` excludes members of the listed SonarQube groups.
Excluded, unmatched, ambiguous,
and unknown-state users are protected from permission revocation.
A matched user with a recognized inactive GitLab state
receives no desired project permissions,
so GUASSP removes that user's managed direct permissions.

`users.deactivation` is disabled by default.
When enabled, GUASSP also deactivates the matched SonarQube account globally
when GitLab reports `blocked`, `banned`, `deactivated`,
`ldap_blocked`, or `blocked_pending_approval`.
This affects the account across SonarQube projects
and can revoke its tokens; it is not a project-only access change.
See SonarQube's [deactivation behavior][sonar deactivation].
Unknown GitLab states do not trigger deactivation.

### Project permissions

With no custom map, GitLab access levels map cumulatively:

* `10` Guest: `user`
* `20` Reporter: `user`, `codeviewer`
* `30` Developer: previous permissions plus `issueadmin`
* `40` Maintainer: previous permissions plus `securityhotspotadmin`
* `50` Owner: previous permissions plus `admin`

The map uses exact numeric GitLab access levels.
A custom `permissions` map replaces the defaults.
For an unmapped level, GUASSP leaves the user's current permissions unchanged.
An empty list means no permissions from the managed set.
Every permission named anywhere in the active map belongs to that managed set
and may be granted or revoked;
permission names absent from the map are never changed.
Use permission names supported by your SonarQube edition.

### Visibility and discovery

By default, GitLab `public` maps to SonarQube `public`;
`internal` and `private` map to `private`.
A custom `visibility.map` replaces these defaults
and must include every source visibility that can occur.
Set `visibility.enabled: false` to leave SonarQube visibility unchanged.

ALM bindings are the normal project lookup.
Enable `discovery.path_fallback` only when a binding is unavailable.
It selects a SonarQube project only when exactly one unbound project's name
equals the full GitLab namespace path; otherwise it skips the target.

## HTTP endpoints

* `POST /api/v1/sync`
  asks GitLab to validate the job token, then queues its project.
* `POST /api/v1/projects/sync`
  accepts `{"project":"group/project"}` and queues a manually selected project.
  It is available when `web.enabled` is true.
* `POST /api/v1/full-sync`
  refreshes project bindings and queues every discovered project.
  It is available only when `discovery.manual_full_sync` is true.
* `GET /api/v1/status`
  returns service, scheduler, discovery, and upstream status.
* `GET /api/v1/runs?limit=N`
  returns recent reconciliation results
  (default 50; retention is controlled by `runtime.run_history`).
* `GET /`
  serves the manual form, `POST /` submits it, and `GET /stats`
  serves status pages with 25 runs per page; these routes require `web.enabled`.
* `GET /healthz`
  reports process liveness without probing upstreams.
* `GET /readyz`
  reports whether startup preflight passed.
* `GET /metrics`
  serves Prometheus metrics when `metrics.enabled` is true.

Set `web.base_path: /guassp` when the service is published below a URL path.
Page links, form submissions, and displayed endpoint URLs use this prefix,
and the service accepts both prefixed and root paths.
A reverse proxy can preserve the prefix or strip it before forwarding requests.

When set, `api.token` requires `Authorization: Bearer <token>`
on every JSON API endpoint, including status and run history.
CI sync still needs its job token in `JOB-TOKEN`.
Without `api.token`, status and run history are public;
CI sync still validates the GitLab job token.
Set both `web.username` and `web.password`
to protect the browser interface and form-based sync.
When `api.token` is unset, those credentials also protect manual JSON sync.
Set both web credentials or neither.
`web.sync_rate` limits manual sync requests by the remote IP seen by GUASSP;
behind a proxy, that may be the proxy's IP.

Metrics are enabled and unauthenticated by default.
Protect `/metrics` with either `metrics.token` (Bearer)
or both `metrics.username` and `metrics.password` (Basic);
do not configure both methods.
Set `metrics.include_runtime: true` to include Go runtime and process metrics.
These credentials are separate from the web and API credentials.
The HTTP listener does not provide TLS;
terminate TLS at a trusted proxy
or ingress before exposing it outside a private network.

Disabling `web.enabled` removes the pages and manual sync routes but leaves
CI sync, status, run history, health checks, and enabled metrics available.
`compat.job_token_body: true` additionally accepts a JSON `job_token`
for CI sync; leave it disabled when the client can send a request header.

<!-- links -->

[permissions scheme]: ./permissions.drawio.png
[config example]: ./internal/config/generated/guassp.example.yaml
[config]: ./CONFIG.md
[kustomize]: ./deploy/kustomize/README.md
[macOS amd64]: https://github.com/WoozyMasta/guassp/releases/latest/download/guassp-darwin-amd64
[macOS arm64]: https://github.com/WoozyMasta/guassp/releases/latest/download/guassp-darwin-arm64
[Linux amd64]: https://github.com/WoozyMasta/guassp/releases/latest/download/guassp-linux-amd64
[Linux arm64]: https://github.com/WoozyMasta/guassp/releases/latest/download/guassp-linux-arm64
[Windows amd64]: https://github.com/WoozyMasta/guassp/releases/latest/download/guassp-windows-amd64.exe
[Windows arm64]: https://github.com/WoozyMasta/guassp/releases/latest/download/guassp-windows-arm64.exe
[gitlab tokens]: https://docs.gitlab.com/security/tokens/
[token scopes]: https://docs.gitlab.com/security/tokens/access_token_scopes/
[job tokens]: https://docs.gitlab.com/ci/jobs/ci_job_token/
[gitlab member API]: https://docs.gitlab.com/api/project_members/#list-all-members-of-a-project
[sonar tokens]: https://docs.sonarsource.com/sonarqube-server/user-guide/managing-tokens
[sonar permissions]: https://docs.sonarsource.com/sonarqube-server/instance-administration/user-management/user-permissions
[sonar deactivation]: https://docs.sonarsource.com/sonarqube-server/instance-administration/user-management/deactivating-users
