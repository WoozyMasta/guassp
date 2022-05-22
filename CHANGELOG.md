# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.2.0](https://github.com/WoozyMasta/guassp/releases/tag/0.1.1) - 2022-05-22

### Added

* `/task_manual/<int:prj_id>` endpoint;
* Workaround for searching for a project by the full name of the project in
  SonarQube if the search for ALM integration was unsuccessful.  
  A fully qualified name equal to `$CI_PROJECT_NAMESPACE/$CI_PROJECT_NAME` or
  `project.path_with_namespace` is recommended when registering a project.
* An item with [requirements](README.md#requirements) for the normal operation
  of the solution has been added to the project documentation

### Changed

* Only the project ID is published to the queue, the full status of the task was
  previously published, which could lead to data disclosure.
* Update project preparation script example `extra/sq-integration-taks.sh`,
  updated logic for searching and creating a project

## [0.1.1](https://github.com/WoozyMasta/guassp/releases/tag/0.1.1) - 2022-05-06

### Added

* `/health` endpoint;
* docker-compose example;
* nginx config example;
* improve documentation.

## [0.1.0](https://github.com/WoozyMasta/guassp/releases/tag/0.1.0) - 2022-05-06

### Added

* First dev release
