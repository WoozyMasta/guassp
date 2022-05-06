#!/usr/bin/env bash

# Copyright 2022 WoozyMasta aka Maxim Levchenko <me@woozymasta.ru>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

set -euo pipefail
: "${CI_DEBUG_TRACE:=${DEBUG:=}}"
if [ "${CI_DEBUG_TRACE,,}" == 'true' ]; then
  set -x; debug_sh="sh -x"; debug_curl=--verbose
else
  debug_sh='sh'; debug_curl=--silent
fi

# SonarQube
: "${SONARQUBE_URL?SonarQube sonarqube server root url not specified}"
: "${SONARQUBE_TOKEN?Token for connecting to the SonarQube was not specified}"
: "${SONARQUBE_PROJECT_KEY:=gitlab:$CI_PROJECT_ID}"
: "${SONARQUBE_PROJECT_NAME:=$CI_PROJECT_NAMESPACE/$CI_PROJECT_NAME}"
: "${SONARQUBE_QUALITYGATE_WAIT:=true}"
: "${SONARQUBE_QUALITYGATE_TIMEOUT:=300}"
: "${SONARQUBE_LOG_LEVEL:=INFO}"
: "${SONARQUBE_VERBOSE:=true}"
# OWASP Dependency Check
: "${OWASP_DEPENDENCY_CHECK_DB_STRING?PostgreSQL DB connection not specified}"
: "${OWASP_DEPENDENCY_CHECK_DB_PASSWORD?PostgreSQL DB password not specified}"
: "${OWASP_DEPENDENCY_CHECK_DB_USER?PostgreSQL DB user not specified}"
# Skip stages
: "${SKIP_DEPENDENCY_CHECK_JOB:=false}"
: "${SKIP_SONARQUBE_PREPARE:=false}"
: "${SKIP_SONARQUBE_SYNC:=false}"
: "${SKIP_SONARQUBE_COVERAGE:=false}"
# Version of analyzed project
version="${CI_COMMIT_REF_NAME:-MR-${CI_MERGE_REQUEST_IID:-0}}"
# Feedback contact
: "${SUPPORT_CONTACTS:=Contact for support <dev@null.tld>}"


# Functions
# -----------------------------------------------------------------------------
# GitLab log separator
section-start() {
  section="${1//[-_\. ]/_}"; shift
  printf '\e[0Ksection_start:%s:%s[collapsed=true]\r\e[0K\e[1;36m%s\e[0m\n' \
    "$(date +%s)" "$section" "$*"
}
section-end() {
  printf '\e[0Ksection_end:%s:%s\r\e[0K\n' "$(date +%s)" "${section:-}"
  section=''
}

# Messages
fail() { section-end; >&2 printf '\e[1;31m%s\e[0m\n' "$*"; exit 1; }
warn() { >&2 printf '\e[1;33m%s\e[0m\n' "$*"; }
info() { printf '\e[1;34m%s\e[0m\n' "$*"; }

# Check string is boolean True
is-true() {
  grep --perl-regexp --ignore-case --quiet '^(true|on|yes|1)$' <<< "$1"
}

# Wrapper for curl SonarQube
sq-api() {
  local path="$1"; shift
  curl --location --fail $debug_curl --user "${SONARQUBE_TOKEN:-}:" \
    "${SONARQUBE_URL:-}/api/$path" "${@}"
}


# Prepare
# -----------------------------------------------------------------------------
if ! is-true "$SKIP_SONARQUBE_PREPARE"; then
  # Check default brnach name
  section-start prepare 'Preparing to run the SonarQube Scanner'

  # Try create project in SQ
  if sq-api projects/create -o /dev/null \
    -d "name=$SONARQUBE_PROJECT_NAME" \
    -d "project=$SONARQUBE_PROJECT_KEY"
  then
    info "Project $SONARQUBE_PROJECT_NAME with " \
      "key $SONARQUBE_PROJECT_KEY created in SonarQube"
  fi

  # Get branches list data
  sq_branches="$(
    sq-api project_branches/list -d "project=$SONARQUBE_PROJECT_KEY"
  )"

  # Let's check if the default branch for the project was previously analyzed.
  # If there has not been an analysis yet and the current analysis is
  # not started for the default branch, then we issue an error that the
  # default branch of the project must first be analyzed.
  # Otherwise, problems arise with the first analysis of the project.

  if ! jq \
    -er '.branches[] | select(.isMain==true) | .status[]' <<< "$sq_branches" \
    > /dev/null
  then
    if [ "${CI_COMMIT_BRANCH:-none}" != "$CI_DEFAULT_BRANCH" ]; then
      fail  \
        "This is the first analyze of the project $SONARQUBE_PROJECT_NAME " \
        "($SONARQUBE_PROJECT_KEY), and you are trying to do it not from the " \
        "default branch, but from $version. This action is not allowed, " \
        "you must first run analyze on the default ($CI_DEFAULT_BRANCH) " \
        'branch, only then will you be able to parse merge requests, tags, ' \
        "and other branches. $SUPPORT_CONTACTS"
    fi
  fi

  # Get name of current default branch in SQ
  sq_curent_branch="$(
    jq -er '.branches[] | select(.isMain==true) | .name' <<< "$sq_branches"
  )"

  # Rename SQ default branch to default branch in GL if they are not the same
  if [ "$sq_curent_branch" != "$CI_DEFAULT_BRANCH" ]; then
    sq-api project_branches/rename \
      -d "project=$SONARQUBE_PROJECT_KEY" \
      -d "name=$CI_DEFAULT_BRANCH" &&
    warn "SonarQube default project branch renamed to $CI_DEFAULT_BRANCH"
  fi

  # Setup ALM integration
  sq-api alm_settings/set_gitlab_binding \
    -d "almSetting=$SONARQUBE_ALM_NAME" \
    -d "project=$SONARQUBE_PROJECT_KEY" \
    -d "repository=$CI_PROJECT_ID" &&
  info "SonarQube ALM integration to GitLab updated"

  section-end
else
  warn 'Preparing SonarQube skiped by flag SKIP_SONARQUBE_PREPARE=true'
fi


# SonarQube project users access sync with GitLab
# -----------------------------------------------------------------------------
if ! is-true "$SKIP_SONARQUBE_SYNC"; then
  section-start 'guassp' "SonarQube project users access sync with GitLab"
  curl -Lf "$SONARQUBE_URL:5000/task" -H "JOB-TOKEN: $CI_JOB_TOKEN" | jq -er
  section-end
else
  warn 'SonarQube project access sync skiped by flag SKIP_SONARQUBE_SYNC=true'
fi


# SonarQube Scanner Args
# -----------------------------------------------------------------------------
# Default array of arguments for SonarScanner
sq_args=(
  "-Dsonar.qualitygate.wait=$SONARQUBE_QUALITYGATE_WAIT"
  "-Dsonar.qualitygate.timeout=$SONARQUBE_QUALITYGATE_TIMEOUT"
  "-Dsonar.links.homepage=$CI_PROJECT_URL"
  "-Dsonar.links.ci=$CI_PROJECT_URL/-/pipelines"
  "-Dsonar.links.issue=$CI_PROJECT_URL/-/issues"
  "-Dsonar.links.scm=$CI_PROJECT_URL/-/tree/$CI_DEFAULT_BRANCH"
  "-Dsonar.host.url=$SONARQUBE_URL"
  "-Dsonar.login=$SONARQUBE_TOKEN"
  "-Dsonar.log.level=$SONARQUBE_LOG_LEVEL"
  "-Dsonar.verbose=$SONARQUBE_VERBOSE"
)

# Additional DependencyCheck arguments for SonarScanner
if ! is-true "$SKIP_DEPENDENCY_CHECK_JOB"; then
  dc_report=dependency-check-report
  sq_args+=(
    "-Dsonar.dependencyCheck.severity.blocker=9.0"
    "-Dsonar.dependencyCheck.severity.critical=7.0"
    "-Dsonar.dependencyCheck.severity.major=4.0"
    "-Dsonar.dependencyCheck.severity.minor=0.0"
    "-Dsonar.dependencyCheck.jsonReportPath=$CI_PROJECT_DIR/$dc_report.json"
    "-Dsonar.dependencyCheck.htmlReportPath=$CI_PROJECT_DIR/$dc_report.html"
    "-Dsonar.exclusions=$dc_report.html"
  )
fi

# Specify arguments for Merge Request analyze
if [ "${CI_PIPELINE_SOURCE:-}" == 'merge_request_event' ]; then
  sq_args+=(
    "-Dsonar.pullrequest.key=$CI_MERGE_REQUEST_IID"
    "-Dsonar.pullrequest.branch=$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"
    "-Dsonar.pullrequest.base=$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
  )
  coverage_reference="pullRequest=$CI_MERGE_REQUEST_IID"

# Specify arguments for tag analyze
elif [ -n "${CI_COMMIT_TAG:-}" ]; then
  sq_args+=("-Dsonar.projectVersion=$CI_COMMIT_TAG")
  sq_args+=("-Dsonar.branch.name=$CI_COMMIT_TAG")
  coverage_reference="branch=$CI_COMMIT_TAG"

# Set args for branch analyze
elif [ -n "${CI_COMMIT_BRANCH:-}" ]; then
  sq_args+=("-Dsonar.branch.name=$CI_COMMIT_BRANCH")
  coverage_reference="branch=$CI_COMMIT_BRANCH"
fi


# Dependency Check
# -----------------------------------------------------------------------------
if ! is-true "$SKIP_DEPENDENCY_CHECK_JOB"; then
  section-start 'dependency' 'Analyzing dependencies with DependencyCheck'

  dc_log_name="$CI_PROJECT_NAME-$CI_COMMIT_REF_SLUG.log"

  $debug_sh /opt/dependency-check/bin/dependency-check.sh \
    --noupdate \
    --project "$SONARQUBE_PROJECT_NAME:$version ($SONARQUBE_PROJECT_KEY)" \
    --out "$CI_PROJECT_DIR" \
    --scan "$CI_PROJECT_DIR" \
    --format JSON \
    --format HTML \
    --enableExperimental \
    --dbDriverName=org.postgresql.Driver \
    --connectionString "$OWASP_DEPENDENCY_CHECK_DB_STRING" \
    --dbPassword "$OWASP_DEPENDENCY_CHECK_DB_PASSWORD" \
    --dbUser "$OWASP_DEPENDENCY_CHECK_DB_USER" \
    --cveValidForHours 24 \
    --log "$CI_PROJECT_DIR/$dc_log_name" ||
  fail \
    'Error run DependencyCheck analyzing, ' \
    "$SUPPORT_CONTACTS"

  info "For more details, check the analyzer log in the ./$dc_log_name file"

  section-end
else
  warn 'DependencyCheck analyzing skiped by flag SKIP_DEPENDENCY_CHECK_JOB=true'
fi


# Running the SonarQube Scanner
# -----------------------------------------------------------------------------
section-start 'scanner' "Run SonarQube scanner"
sonar-scanner \
  -Dsonar.projectKey="$SONARQUBE_PROJECT_KEY" \
  -Dsonar.projectName="$SONARQUBE_PROJECT_NAME" \
  "${sq_args[@]}"
section-end


# Get coverage from SonarQube API
# -----------------------------------------------------------------------------
if ! is-true "$SKIP_SONARQUBE_COVERAGE"; then
  section-start 'coverage' "Get code coverage from SonarQube"

  coverage=$(
    sq-api measures/component \
      -d "component=$SONARQUBE_PROJECT_KEY" \
      -d "metricKeys=coverage" \
      -d "$coverage_reference" |
    jq -er '.component.measures[] | select(.metric == "coverage") | .value' || :
  )

  section-end
  if [ -n "$coverage" ]; then
    info "SonarQube coverage $coverage%"
  else
    warn 'SonarQube coverage was not received'
  fi
else
  warn 'SonarQube coverage request skiped by flag SKIP_SONARQUBE_COVERAGE=true'
fi
