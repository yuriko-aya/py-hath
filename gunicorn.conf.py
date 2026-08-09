import os

import gunicorn

gunicorn.SERVER = 'Genetic Lifeform and Distributed Open Server 0.1-py '

workers = int(os.environ.get('HATH_WORKERS', '4'))
worker_class = os.environ.get('HATH_WORKER_CLASS', 'sync')

# gevent/eventlet only: concurrent connections per worker
worker_connections = int(os.environ.get('HATH_WORKER_CONNECTIONS', '1000'))

# Drop stuck clients (incomplete SSL/HTTP) quickly; gevent handles concurrency
timeout = int(os.environ.get('HATH_TIMEOUT', '10'))
keepalive = 0

max_requests = 1000
max_requests_jitter = 100

accesslog = os.environ.get('HATH_ACCESSLOG', 'log/gunicorn_access.log')
errorlog = os.environ.get('HATH_ERRORLOG', 'log/gunicorn_error.log')
loglevel = os.environ.get('HATH_LOGLEVEL', 'info')
pidfile = os.environ.get('HATH_PIDFILE', 'config/gunicorn.pid')

bind = os.environ.get('HATH_BIND', '0.0.0.0:443')
certfile = os.environ.get('HATH_CERTFILE')
keyfile = os.environ.get('HATH_KEYFILE')

ciphers = "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS"
