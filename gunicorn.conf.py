import gunicorn
import logging
import ssl
import sys

gunicorn.SERVER = 'Genetic Lifeform and Distributed Open Server 0.1-py '

# Workers
workers = 4
worker_class = "gevent"

# Connections
timeout = 30
keepalive = 0

# Restart workers after a certain number of requests
max_requests = 1000
max_requests_jitter = 100

# Logging
accesslog = "log/gunicorn_access.log"
errorlog = "log/gunicorn_error.log"
loglevel = "info"

# SSL/TLS
ciphers = "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS"
