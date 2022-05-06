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

# Log date format
fmt='%Y-%m-%d %H:%M'

# Default mode arg
: "${arg:=${1:-worker}}"
[ -n "${1:-}" ] && shift

# Vars
: "${LISTEN_ADDRESS:=0.0.0.0}"
: "${LISTEN_PORT:=5000}"
: "${EXPORTER_LISTEN_ADDRESS:=0.0.0.0}"
: "${EXPORTER_LISTEN_PORT:=9726}"
: "${REDIS_URL:=redis://localhost:6379/0}"
: "${LOG_LEVEL:=INFO}"

log() {
  local lvl="$1"; shift
  printf '%s [%s] %s\n' "$(date "+$fmt")" "${lvl^^}" "${*}"
}

# shellcheck source=/dev/null
[ -f ./.venv/bin/activate ] && . ./.venv/bin/activate


exporter=(
  rq-exporter
    --host "$EXPORTER_LISTEN_ADDRESS"
    --port "$EXPORTER_LISTEN_PORT"
    --log-level "$LOG_LEVEL"
    --log-format '%(asctime)-15s [%(levelname)s] %(message)s'
    --log-datefmt "$fmt"
    --redis-url "$REDIS_URL"
)

if [ "$arg" == 'api-dev' ]; then
  log info "Run API application in DEV mode on $LISTEN_ADDRESS:$LISTEN_PORT"
  exec ./app.py

elif [ "$arg" == 'api' ]; then
  log info "Run API WSGI application on $LISTEN_ADDRESS:$LISTEN_PORT"
  exec ./wsgi.py

elif [ "$arg" == 'exporter' ]; then
  log info 'Run queue metrics exporter'
  exec "${exporter[@]}" "${@}"

elif [ "$arg" == 'worker' ]; then
  log info "Run queue worker with Redis $REDIS_URL"
  exec ./worker.py

elif [ "$arg" == 'all-in-one' ]; then
  log info "Run all applications at once, API on" \
     "$LISTEN_ADDRESS:$LISTEN_PORT, queue worker and exporter" \
  ./worker.py &
  "${exporter[@]}" "${@}" &
  exec ./wsgi.py

else
  >&2 log error \
    'An unexpected error has occurred, valid arguments are:' \
    'worker (default), api, exporter, all-in-one, api-dev'
  exit 1
fi
