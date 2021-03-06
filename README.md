<!-- omit in toc -->
# Guassp - GitLab User Access Synchronizer for SonarQube Projects

The project is intended to create a multi-user integration of [SonarQube][] and
[GitLab][]. Project visibility and user permissions will be set in SonarQube
in the same way as project permissions in GitLab.

> This document is available in languages: [eng π¬π§][], [ua πΊπ¦][], [rus π·πΊ][]

* [Implementation](#implementation)
* [Requirements](#requirements)
* [Components](#components)
* [Container image](#container-image)
* [Quick start](#quick-start)
* [Configuration](#configuration)
* [API](#api)
* [Pipeline](#pipeline)
* [Metrics](#metrics)
* [Building and Debugging](#building-and-debugging)

## Implementation

This utility consists of a front-end API that accepts requests to update
permissions from the GitLab CI pipeline, where all trust is [built around][jt]
`CI_JOB_TOKEN`, trusted tasks are added to the RQ job queue (Redis Queue).
Jobs are processed by the backend workers, and a separate prometheus metrics
exporter is used to display statistics.

![scheme][]

Permissions are divided by the access level of SonarQube roles according to
the interests of group users in GitLab.  
It takes into account how GitLab implements user access rights in the
project, and users from invited groups, where access levels are limited
in accordance with GitLab.

![permissions][]  
![role-mapping][]

## Requirements

### Necessarily

* SonarQube must have configured [ALM][] integration with your GitLab, and you
  must specify the name of the integration key in `SONARQUBE_ALM_KEY`;
* Authentication in SonarQube must occur only through [ALM][] GitLab, otherwise
  the search for users will be violated, the rights are synchronized only for
  the explicitly corresponding account that came from GitLab;
* You must be able to provide an access token with administrative privileges to
  SonarQube in `SONARQUBE_TOKEN` for the worker to work correctly;
* You must create a service user in GitLab, which must have at least
  **developer** access in all projects that you want to analyze in SonarQube,
  with this user you must log in to SonarQube and give him global rights to
  perform analysis and create projects. Then you can use that user's token:
  * User token received in SonarQube as `SONARQUBE_TOKEN` used in CI pipeline to
    perform analysis and project management.
  * User token received in GitLab as `GITLAB_TOKEN` for worker, needed to get a
    list of all members of a group or project, including inherited and invited
    members
* The name of the project registered in SonarQube must be equal to
  `$CI_PROJECT_NAMESPACE/$CI_PROJECT_NAME` and the project key is recommended to
  be set to `gitlab:$CI_PROJECT_ID`. Only with these settings, synchronization
  will be successful, other states are possible but have not been tested.

### Recommended

* The best experience will be gained by using the
  [sonarqube-community-branch-plugin][] plugin which adds branch analysis and PR
  support to your projects. Also here you will need a previously created system
  user in GitLab with **developer** rights, which will allow you to decorate MR
  in your projects.
* For transparent integration, it is best to use the example script
  [sq-integration-taks] for the GitLab CI pipeline, otherwise other project
  registration options may not work correctly or even break the work. The
  example is also tailored for the presence of the
  [sonarqube-community-branch-plugin][] plugin and the execution of OWASP
  DependencyCheck
* Use Prometheus and Grafana metrics to analyze synchronizer performance.

## Components

The project is implemented on [flask][], for WSGI it is used [bjoern][],
the work with the GitLab API is done through [python-gitlab][], and the
SonarQube API through [python-sonarqube-api][]. To process the message
queue, [RQ][rq] is used, whose metrics are returned by [rq-exporter][].

## Container image

You can pull image from registries:

* [`ghcr.io/woozymasta/guassp:latest`][ghcr]
* [`quay.io/woozymasta/guassp:latest`][quay]
* [`docker.io/woozymasta/guassp:latest`][dhub]

## Quick start

For a quick start, you can use the example from [docker-compose][]:

1. [docker-compose.env][] - change the settings in the environment file
2. [docker-compose.yml][] - run with `docker-compose up -d`

## Configuration

To launch the desired utility, transfer to the container or script
`guassp.sh` argument:

* `worker` _(default)_ - task handler from the queue
* `api` - API to control tasks
* `exporter` - Prometheus metric
* `all-in-one` - Launch `worker`,`api` and `exporter` immediately
* `api-dev` - Launching API via Flask DEV server

### Application Options

* **`LISTEN_ADDRESS`**=`0.0.0.0` - API listen address
* **`LISTEN_PORT`**=`5000` - API listen port
* **`LOG_LEVEL`**=`INFO` - Logging level
* **`SECRET_KEY`**=`secret` - Secret key
* **`QUEUE_RESULT_TTL`**=`7200` - Queue result storage time
* **`MORE_ACCURATE_SYNC`**=`true` - Search users in SonarQube by GitLab
  email else by username. It call one more API request per user is
  more accurate but slower x2

### Options for working with GitLab

* **`GITLAB_URL`**=`https://gitlab.com` - GitLab server URL
* **`GITLAB_TOKEN`** - GitLab access token, must have permissions to view
  contributors and their permissions for maintained projects
* **`GITLAB_SKIP_USERS`** - comma-separated list of GitLab user IDs that will
  be skipped during synchronization

### Options for working with SonarQube

* **`SONARQUBE_URL`** - SonarQube server URL
* **`SONARQUBE_TOKEN`** - access token to SonarQube with
  administrative privileges
* **`SONARQUBE_ALM_KEY`** - [ALM][] key GitLab integration name
* **`SONARQUBE_SKIP_GROUPS`** - comma-separated list of SonarQube groups that
  will be skipped during synchronization

### Options for working with Redis

* **`REDIS_URL`**=`redis://localhost:6379/0` - Redis server URL

### Prometheus Metrics Exporter Options

* **`EXPORTER_LISTEN_ADDRESS`**=`0.0.0.0` - Exporter listen address
* **`EXPORTER_LISTEN_PORT`**=`9726` - Exporter listen port

Also you can pass [RQ][rq] args and environment variables

## API

### Job Registration

> POST **`/task`**
>
> ```json
> {"job_token": str}
> ```
>
> Headers: `JOB-TOKEN` or `Authorization: Bearer`

You need to pass the task token in any of the options:

```bash
curl -sL http://127.0.0.1:5000/task \
  -H "Content-Type: application/json" \
  -d '{"job_token": "'$CI_JOB_TOKEN'"}' | jq

curl -sL http://127.0.0.1:5000/task -X POST \
  -H "JOB-TOKEN: $CI_JOB_TOKEN" | jq

curl -sL http://127.0.0.1:5000/task -X POST \
  -H "Authorization: Bearer $CI_JOB_TOKEN" | jq
```

The task token can be passed in the `JOB-TOKEN` header, or
`Authorization: Bearer` or be the value of the `job_token` key in JSON

### Tasks Queue

> GET **`/tasks`**

```bash
curl -sL http://127.0.0.1:5000/tasks | jq
curl -sL http://127.0.0.1:5000/tasks | jq -er '.tasks | keys'
```

### Task Status

> GET **`/task/<uuid:job_uuid>`**

```bash
curl -sL http://127.0.0.1:5000/task/8b155172-cfcf-4777-b9f4-bfce53b6eb0e | jq
```

### Removing a task from the queue

> DELETE **`/task/<uuid:job_uuid>`**

```bash
curl -sL http://127.0.0.1:5000/task/8b155172-cfcf-4777-b9f4-bfce53b6eb0e \
  -X DELETE | jq
```

### Manual task registration by GitLab project ID

> POST **`/task_manual/<int:prj_id>`**

```bash
curl -sL http://127.0.0.1:5000/task_manual/111 \
  -X POST | jq
```

### Health

> GET **`/health`**

API health, application availability and job queues.

## Pipeline

In the GitLab CI pipeline, first of all, you must make sure that the [ALM][]
setup is done and refers to your project, after which you can submit
a task for synchronization in guassp. Now you can start the analysis.

For publish Guassp API behind Nginx as part of SonarQube API check
[Nginx config example][]

```bash
: "${SONARQUBE_PROJECT_KEY:=gitlab:$CI_PROJECT_ID}"

curl --location --fail --user "$SONARQUBE_TOKEN:" \
  "$SONARQUBE_URL/api/alm_settings/set_gitlab_binding" \
  -d "almSetting=$SONARQUBE_ALM_NAME" \
  -d "project=$SONARQUBE_PROJECT_KEY" \
  -d "repository=$CI_PROJECT_ID"

curl --location --fail -X POST -H "JOB-TOKEN: $CI_JOB_TOKEN" \
  "$SONARQUBE_URL/api/guassp/task"
```

You can see a more voluminous example of a script for executing SonarQube
in the pipeline in the [`sq-integration-taks.sh`][sq-integration-taks] file

## Metrics

Metrics implemented using project [rq-exporter][]

Dashboard ID `12196` is suitable for visualization in Grafana or use it
[adaptation][dashboard] which will output only metrics from guassp.

## Building and Debugging

A set of commands for fast local debugging in container

```bash
# Build
podman build -t guassp .

# Redis
podman run --rm -d -p 6379:6379 --name redis redis
# API
podman run --rm -d -p 5000:5000 --env-file .env --name guassp-api localhost/guassp:latest api
# Workers
podman run --rm -d --env-file .env --name guassp-worker-1 localhost/guassp:latest worker
podman run --rm -d --env-file .env --name guassp-worker-2 localhost/guassp:latest worker
# Exporter
podman run --rm -d -p 9726:9726 --env-file .env --name guassp-exporter localhost/guassp:latest exporter

# Check
curl 0.0.0.0:9726 -s | grep -v '^#'
curl 0.0.0.0:5000/tasks -s | jq
curl 0.0.0.0:5000/task -s -X POST -H "JOB-TOKEN: $CI_JOB_TOKEN" | jq
```

Or run locally, for this you need to install dependencies

```bash
apt-get install -y libev-dev libevdev2
python -m venv .venv
./.venv/bin/activate
pip install requirements.txt
```

And for simplicity, run through a script `guassp`

```bash
./guassp.sh api
./guassp.sh worker
./guassp.sh exporter
```

<!-- Links files -->
[eng π¬π§]: README.md
[ua πΊπ¦]: extra/README-ua.md
[rus π·πΊ]: extra/README-ru.md
[scheme]: extra/scheme.drawio.png
[permissions]: extra/permissions.drawio.png
[role-mapping]: extra/role-mapping.png
[dashboard]: extra/grafana-dashboard.json
[docker-compose.env]: extra/docker-compose.env
[docker-compose.yml]: extra/docker-compose.yml
[Nginx config example]: extra/nginx.conf
[sq-integration-taks]: extra/sq-integration-taks.sh

<!-- Links web -->
[GitLab]: https://about.gitlab.com
[SonarQube]: https://www.sonarqube.org
[jt]: https://docs.gitlab.com/ee/api/jobs.html#get-job-tokens-job
[flask]: https://github.com/pallets/flask
[bjoern]: https://github.com/jonashaag/bjoern
[python-gitlab]: https://github.com/python-gitlab/python-gitlab
[python-sonarqube-api]: https://github.com/shijl0925/python-sonarqube-api
[rq]: https://github.com/rq/rq
[rq-exporter]: https://github.com/mdawar/rq-exporter
[docker-compose]: https://docs.docker.com/compose/
[sonarqube-community-branch-plugin]: https://github.com/mc1arke/sonarqube-community-branch-plugin

<!-- Containers -->
[quay]: https://quay.io/repository/woozymasta/guassp
[dhub]: https://hub.docker.com/r/woozymasta/guassp
[ghcr]: https://github.com/WoozyMasta/guassp/pkgs/container/guassp
