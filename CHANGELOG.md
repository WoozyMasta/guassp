<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog][],
and this project adheres to [Semantic Versioning][].

## [0.3.0][] - 2026-10-28

### Changed

* Rebuilt Guassp as a Go service, replacing the previous Python application
  and its Redis/RQ runtime with an in-memory scheduler.
* Introduced YAML and JSON configuration with environment-variable expansion,
  optional `.env` loading, and generated schema and example files.

### Added

* Added synchronization of GitLab project access
  with SonarQube through ALM bindings,
  with configurable permission and visibility mappings, user matching,
  and optional deactivation of inactive users.
* Added CI and manual synchronization endpoints,
  a web interface for service status and run history,
  health and readiness probes, and optional protected Prometheus metrics.
* Added a configurable HTTP path prefix and run-history retention,
  plus Kustomize resources for deployment.

[0.3.0]: https://github.com/WoozyMasta/guassp/compare/0.2.0...v0.3.0

## [0.2.0][] - 2022-05-22

### Added

* `/task_manual/<int:prj_id>` endpoint;
* Workaround for searching for a project by the full name of the project in
  SonarQube if the search for ALM integration was unsuccessful.  
  A fully qualified name equal to `$CI_PROJECT_NAMESPACE/$CI_PROJECT_NAME` or
  `project.path_with_namespace` is recommended when registering a project.
* An item with requirements (see `README.md`) for the normal operation
  of the solution has been added to the project documentation

### Changed

* Only the project ID is published to the queue, the full status of the task was
  previously published, which could lead to data disclosure.
* Update project preparation script example `extra/sq-integration-taks.sh`,
  updated logic for searching and creating a project

[0.2.0]: https://github.com/WoozyMasta/guassp/compare/0.1.1...0.2.0

## [0.1.1][] - 2022-05-06

### Added

* `/health` endpoint;
* docker-compose example;
* nginx config example;
* improve documentation.

[0.1.1]: https://github.com/WoozyMasta/guassp/compare/0.1.0...0.1.1

## [0.1.0][] - 2022-05-06

### Added

* First dev release

[0.1.0]: https://github.com/WoozyMasta/guassp/v0.1.0

<!--links-->
[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
