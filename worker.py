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

from dotenv import load_dotenv
import redis

# Load .env
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

# Logging
loglevel = (os.environ.get('LOG_LEVEL', 'info')).upper()
if loglevel != 'DEBUG':
    LOGFORMAT = '%(asctime)-15s [%(levelname)s] %(message)s'
    logging.basicConfig(
        level=loglevel, format=LOGFORMAT, datefmt='%Y-%m-%d %H:%M')
else:
    LOGFORMAT = (
        '%(asctime)-15s [%(levelname)s] %(module)s '
        '(%(process)d:%(threadName)s) %(message)s'
    )
    logging.basicConfig(level=loglevel, format=LOGFORMAT)


listen = ['guassp']
redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
conn = redis.from_url(redis_url)

if __name__ == '__main__':
    from rq import Connection, Queue, Worker
    with Connection(conn):
        try:
            worker = Worker(list(map(Queue, listen)))
        except redis.exceptions.ConnectionError as e:
            logging.fatal('Redis: %s', e)
            os.sys.exit(1)
        worker.work()
