#!/usr/bin/env python3

'''
Copyright 2022 WoozyMasta aka Maxim Levchenko <me@woozymasta.ru>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
MA 02110-1301, USA.
'''

import logging
import os
import uuid
from urllib.parse import urljoin

import requests
from dotenv import load_dotenv
from flask import Flask, abort, jsonify, request, url_for
from flask.logging import create_logger
from gitlab import Gitlab, exceptions
from werkzeug.exceptions import HTTPException
from rq import Queue
from rq.job import Job
from sonarqube import SonarQubeClient

from worker import conn

# Env
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

# App
app = Flask(__name__)
app.config['LISTEN_ADDRESS'] = os.environ.get('LISTEN_ADDRESS', '0.0.0.0')
app.config['LISTEN_PORT'] = int(os.environ.get('LISTEN_PORT', 5000))
app.config['LOG_LEVEL'] = os.environ.get('LOG_LEVEL', 'INFO').upper()
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'secret')
app.config['QUEUE_RESULT_TTL'] = os.environ.get('QUEUE_RESULT_TTL', 7200)
# Search users in SQ by GitLab email
# it call one more API request per user but more accurate, slower x2
app.config['MORE_ACCURATE_SYNC'] = bool(
    os.environ.get('MORE_ACCURATE_SYNC', True))
# Dependecies
app.config['GITLAB_URL'] = os.environ.get('GITLAB_URL', 'https://gitlab.com')
app.config['GITLAB_TOKEN'] = os.environ.get('GITLAB_TOKEN')
app.config['GITLAB_SKIP_USERS'] = os.environ.get('GITLAB_SKIP_USERS')
app.config['SONARQUBE_URL'] = os.environ.get('SONARQUBE_URL')
app.config['SONARQUBE_TOKEN'] = os.environ.get('SONARQUBE_TOKEN')
app.config['SONARQUBE_ALM_KEY'] = os.environ.get('SONARQUBE_ALM_KEY')
app.config['SONARQUBE_SKIP_GROUPS'] = os.environ.get('SONARQUBE_SKIP_GROUPS')

# Logging
log = create_logger(app)
log.setLevel(logging.getLevelName(app.config['LOG_LEVEL']))

# Queue
queue = Queue(name='guassp', connection=conn)

# List of SonarQube groups
sonar_groups = [
    'user',
    'codeviewer',
    'issueadmin',
    'securityhotspotadmin',
    'admin',
    'scan'
]
# Mapping GitLab groups to SonarQube groups
group_mapping = {
    10: sonar_groups[:1],  # 10 guest      - user
    20: sonar_groups[:2],  # 20 reporter   - user, code
    30: sonar_groups[:3],  # 30 developer  - user, code, issue
    40: sonar_groups[:4],  # 40 mainteiner - user, code, issue, security
    50: sonar_groups[:5],  # 50 owner      - user, code, issue, security, admin
}

# Ignore users in GL and groups in SQ for update permissions
skip_gitlab = app.config['GITLAB_SKIP_USERS'].replace(' ', '').split(',')
skip_gitlab = set([int(i) for i in skip_gitlab])
skip_sonar = set(
    app.config['SONARQUBE_SKIP_GROUPS'].replace(' ', '').split(','))


def gitlab_connect():
    """Connect to GitLab

    Returns:
        object: GitLab connection
    """
    gitlab = dict(
        url=app.config['GITLAB_URL'],
        private_token=app.config['GITLAB_TOKEN'],
        user_agent='gitlab2sonarqube'
    )

    try:
        gl = Gitlab(**gitlab)
        gl.auth()
        log.debug('Connection open to Gitlab %s %s',
            gitlab['url'], gl.version()[0])
        return gl

    # pylint: disable=broad-except
    except Exception:
        log.exception('Can\'t connect to GitLab %s', gitlab['url'])
        os.sys.exit(1)


def sonarqube_connect():
    """Connect to SonarQube

    Returns:
        object: SonarQube connection
    """

    sonar = dict(
        sonarqube_url=app.config['SONARQUBE_URL'],
        token=app.config['SONARQUBE_TOKEN'],
    )

    try:
        sq = SonarQubeClient(**sonar)
        log.debug('Connection open to SonarQube %s %s',
            sonar['sonarqube_url'], sq.server.get_server_version())
        return sq

    # pylint: disable=broad-except
    except Exception:
        log.exception('Can\'t connect to SonarQube %s', sonar["sonarqube_url"])
        os.sys.exit(1)


def sq_search_key_by_alm(sq: object, project: object, alm_key: str = None):
    """Serch project by ALM key

    Args:
        sq (object): SonarQube connection object
        project (object): GitLab project object generator
        alm_key (str, optional): ALM integration key name. Defaults to None.
    """
    # Set ALM key
    alm_key = alm_key or app.config['SONARQUBE_ALM_KEY']

    # Search project by name in GL ALM projects
    # pylint: disable=unexpected-keyword-arg,no-value-for-parameter
    sq_gl_repos = sq.alm_integrations.search_gitlab_repos(
        almSetting=alm_key,
        projectName=project.name).get('repositories')
    log.debug('Load %d projects from SonarQube by %s ALM and %s name',
        len(sq_gl_repos), alm_key, project.name)

    # Get SQ project key by GL ID
    sq_project_keys = [
        i.get('sqProjectKey') for i in sq_gl_repos if i['id'] == project.id
    ]
    log.debug('Available projects keys: %s', ', '.join(sq_project_keys))

    # Check SQ project key
    if len(sq_project_keys) != 1 or sq_project_keys[0] is None:
        log.error('Projects id %d not found in SonarQube', project.id)
        return
    else:
        return sq_project_keys[0]


def sync_permissions(gl_project_id: int, alm_key: str = None):
    """Sync permissions from GitLab to SonarQube

    Args:
        gl_project_id (int): GitLab project ID
        alm_key (str, optional): ALM integration key name. Defaults to None.
    """

    # Connect to SQ and GL
    sq = sonarqube_connect()
    gl = gitlab_connect()

    # Get GL project by ID
    try:
        gl_project = gl.projects.get(gl_project_id)
        log.debug('Success get project %d data from GitLab', gl_project_id)
    except exceptions.GitlabGetError as e:
        log.error('Projects id %d: %s', gl_project_id, e)
        return

    # Try get SQ project key by ALM
    if sq_project_key := sq_search_key_by_alm(sq, gl_project, alm_key):
        log.debug('Use ALM project with key %s', sq_project_key)

        # Get SQ project data
        sq_projects = list(sq.projects.search_projects(projects=sq_project_key))
        if len(sq_projects) != 1:
            log.error('Projects key %s not matched', sq_project_key)
            return
        else:
            sq_project = sq_projects[0]
            log.info('Use key %s founded by ALM: %s', sq_project_key, alm_key)

    # Search project in SQ by project name
    # $CI_PROJECT_NAMESPACE/$CI_PROJECT_NAME
    else:
        log.debug('Cant find project with ALM %s and try search it', alm_key)
        query = gl_project.path_with_namespace
        sq_projects = list(sq.projects.search_projects(q=query))

        if not sq_projects:
            log.error('Cant find any project by query: %s', query)
            return
        if len(sq_projects) > 1:
            log.error('Found more than one project by query: %s', query)
            return

        sq_project = sq_projects[0]
        sq_project_key = sq_project['key']
        log.info('Use key %s founded by query: %s', sq_project_key, query)


    # Update SQ project visibility as GL project visibility
    if gl_project.visibility != sq_project.get('visibility', 'private'):
        sq.projects.update_project_visibility(
            project=sq_project.get('key'),
            visibility=gl_project.visibility
        )
        log.info('Projects id %s visibility changed to %s',
            gl_project_id, gl_project.visibility)

    # Get GL project members list
    gl_members = gl_project.members_all.list(all=True, per_page=20)

    # Check GL user exist and attach or remove from project in SQ
    for gl_member in gl_members:

        # Skip member ID excluded by GL users rule
        if gl_member.id in skip_gitlab:
            continue

        # Search member in SonarQube
        if app.config['MORE_ACCURATE_SYNC']:
            gl_user = gl.users.get(gl_member.id)
            sq_users = list(sq.users.search_users(gl_user.email))
        else:
            sq_users = list(sq.users.search_users(gl_member.name))

        # Skip if SQ member not match
        if len(sq_users) == 0:
            continue

        # Iterate over returned users from SQ
        for sq_user in sq_users:

            # Skip users not provided by GL
            if sq_user['externalProvider'] != 'gitlab':
                continue

            # Skip member excluded by SQ group rule
            if set(sq_user['groups']) & skip_sonar:
                continue

            # Skip an incorrectly found user
            if sq_user['externalIdentity'] != gl_member.username:
                continue

            # Disable user in SQ if his disabled in GL
            if gl_member.state != 'active' and sq_user['active']:
                sq.users.deactivate_user(login=sq_user['login'])
                log.info('User %s is blocked in project %s',
                    gl_member.username, gl_project_id)
                continue

            # List for exclude setted permissions and remove it from user
            unset_sonar_groups = sonar_groups.copy()

            # Add permissions to user in SQ project as in GL from mapping rule
            for permission in group_mapping[gl_member.access_level]:
                # Set user rights on project
                sq.permissions.add_permission_to_user(
                    login=sq_user['login'],
                    permission=permission,
                    projectKey=sq_project_key
                )
                # Exclude permission (make reversed perms)
                unset_sonar_groups.remove(permission)

            # Remove all another permissions
            for permission in unset_sonar_groups:
                # Unset user rights on project
                sq.permissions.remove_permission_from_user(
                    login=sq_user['login'],
                    permission=permission,
                    projectKey=sq_project_key
                )

            log.info('Projects id %d permissions changed for user %s to: %s',
                gl_project_id, sq_users[0]["externalIdentity"],
                ', '.join(group_mapping[gl_member.access_level]))


def check_uuid(task_uuid: uuid):
    """Check is valid UUID and exist in queue

    Args:
        uuid: RQ task UUID
    """
    try:
        uuid.UUID(task_uuid, version=4)
    except ValueError:
        abort(400, f'Task UUID {task_uuid} is malformed')
    if task_uuid not in queue.job_ids:
        abort(404, f'Task UUID {task_uuid} not found')


@app.errorhandler(Exception)
def handle_error(e: dict):
    """Handler for all HTTP errors

    Args:
        e (dict): error

    Returns:
        tuple: error message, description, code and code
    """
    code = 500
    if not hasattr(e, 'code'):
        message = '500 Internal Server Error'
        description = None
    if isinstance(e, HTTPException):
        code = e.code
        message = e.name
        description = e.description

    log.error('%s %s %s %s %d %s',
        request.remote_addr, request.method, request.scheme,
        request.full_path.rstrip('?'), code, message)

    return jsonify(message=message, description=description, code=code), code


@app.after_request
def after_request(response: object):
    """Add logging for all non 2xx and 3xx responses

    Args:
        response (object): response

    Returns:
        responce: response
    """
    if 'health' in response.json and response.json['health'] == 'healthy':
        return response
    if 200 <= response.status_code <= 399:
        log.info('%s %s %s %s %s',
            request.remote_addr, request.method, request.scheme,
            request.full_path.rstrip('?'), response.status)
    return response


@app.route('/health')
def health():
    """Return health status

    Returns:
        json: healthy if ok
    """
    if key := queue.key:
        return jsonify(health='healthy', key=key)
    else:
        abort(500)


@app.route('/tasks')
def tasks():
    """Return all queued tasks UUID's in RQ

    Returns:
        json: task count and tasks UUID's list
    """
    return jsonify(
        tasks=queue.job_ids,
        started_tasks=queue.started_job_registry.count,
        deferred_tasks=queue.deferred_job_registry.count,
        finished_tasks=queue.finished_job_registry.count,
        failed_tasks=queue.failed_job_registry.count,
        scheduled_tasks=queue.scheduled_job_registry.count
    )


@app.route('/task/<string:task_uuid>')
def get_task(task_uuid: uuid):
    """Return data from task recived from GitLab

    Args:
        task_uuid (uuid): Task UUID

    Returns:
        json: task id, state, job data and ended time
    """
    check_uuid(task_uuid)

    job = Job.fetch(task_uuid, connection=conn)
    return jsonify(
        id=task_uuid, state=job.get_status(refresh=True),
        job=job.args[0], ended_at=job.ended_at)


@app.route('/task/<string:task_uuid>', methods=['DELETE'])
def delete_job(task_uuid: uuid):
    """Delete task from queue by UUID

    Args:
        task_uuid (uuid): Task UUID

    Returns:
        json: task id and state
    """
    check_uuid(task_uuid)

    job = Job.fetch(task_uuid, connection=conn)
    try:
        job.cancel()
    # pylint: disable=broad-except
    except Exception as e:
        abort(500, f'Failed to delete the task for a reason {e}')

    return jsonify(id=task_uuid, state='DELETED')


@app.route('/task', methods=['POST'])
def register_task():
    """Register task in queue by data received from GitLab by CI_JOB_TOKEN

    Returns:
        json: responce
    """

    # Get token from headers or json data
    heads = request.headers
    if heads.get('JOB-TOKEN'):
        token = heads.get('JOB-TOKEN')
    elif 'HTTP_AUTHORIZATION' in heads.environ:
        token = heads.environ.get('HTTP_AUTHORIZATION').replace('Bearer ', '')
    elif request.json and 'job_token' in request.json:
        token = request.json['job_token']
    else:
        abort(401)

    # Check token exist twice
    if not token:
        abort(400, 'Token is invalid or corrupted')

    # Get job status from GitLab
    # https://docs.gitlab.com/ee/api/jobs.html
    gl_jobs_url = urljoin(app.config['GITLAB_URL'], '/api/v4/job')
    gl_jobs_header = {'JOB-TOKEN': str(token)}
    gl_job = requests.get(gl_jobs_url, headers=gl_jobs_header)

    # Forwarding the status from GitLab in case of a problem
    if gl_job.status_code != 200:
        abort(gl_job.status_code, gl_job.reason)

    # Get JSON job data from
    gl_job_state = gl_job.json()

    # Get GitLab job ID
    if 'id' not in gl_job_state:
        abort(400, f'GitLab {gl_jobs_url} did not return job information')
    job_id = gl_job_state['id']

    # Get GitLab project ID
    if 'project_id' not in gl_job_state.get('pipeline'):
        abort(400, f'GitLab {gl_jobs_url} did not return project information')
    prj_id = gl_job_state['pipeline']['project_id']

    # Deduplicate tasks
    for q in queue.jobs:
        if job_id == q.args[0]['id']:
            abort(409, f'Task for job {job_id} already queued {q.id}')
        if prj_id == q.args[0]['pipeline']['project_id']:
            abort(409, f'Task for project {prj_id} already queued {q.id}')

    # Add task to queue
    task = queue.enqueue_call(
        func=sync_permissions,
        args=(prj_id,),
        result_ttl=app.config['QUEUE_RESULT_TTL']
    )

    return jsonify(
        message=f'Task {job_id} added to the queue for project {prj_id}',
        id=task.id
    ), 202, {'Location': url_for('get_task', task_uuid=task.id)}


@app.route('/task_manual/<int:prj_id>', methods=['POST'])
def register_task_manual(prj_id: int):
    """Register task manual in queue by project ID

    Returns:
        json: responce
    """
    # Check prroject ID
    if not prj_id or not isinstance(prj_id, int):
        abort(400, 'Project ID invalid or corrupted')

    # Deduplicate tasks
    for q in queue.jobs:
        if prj_id == q.args[0]['pipeline']['project_id']:
            abort(409, f'Task for project {prj_id} already queued {q.id}')

    # Add task to queue
    task = queue.enqueue_call(
        func=sync_permissions,
        args=(prj_id,),
        result_ttl=app.config['QUEUE_RESULT_TTL']
    )

    return jsonify(
        message=f'Manual task added to the queue for project {prj_id}',
        id=task.id
    ), 202, {'Location': url_for('get_task', task_uuid=task.id)}


if __name__ == '__main__':
    app.run(
        host=app.config['LISTEN_ADDRESS'],
        port=app.config['LISTEN_PORT'],
        debug=app.config['LOG_LEVEL'] == 'DEBUG'
    )
