"""Flask application factory, middleware, and process entry for workers."""

from __future__ import annotations

import logging
import sys
import time

from flask import Flask, g, redirect, request

from hath.config import get_config, load_from_config_file
from hath.logging import setup_file_logging
from hath.metrics import start_metrics_flusher

logger = logging.getLogger(__name__)

app = Flask(__name__)


@app.before_request
def handle_double_slash_in_servercmd():
    """Handle the double slash case in servercmd URLs."""
    g.start_time = time.perf_counter()
    if request.path.startswith('/servercmd/') and '//' in request.path:
        corrected_path = request.path.replace('//', '/')
        if corrected_path != request.path:
            parts = corrected_path.strip('/').split('/')
            if len(parts) >= 4 and parts[0] == 'servercmd':
                command, time_param, key = parts[1], parts[2], parts[3]
                from hath.http.servercmd import servercmd
                return servercmd(command, '', time_param, key)


@app.after_request
def after_request(response):
    """Log the duration of the request."""
    duration = time.perf_counter() - g.start_time
    length = response.headers.get('Content-Length')
    if length is not None:
        size = int(length)
    else:
        data = response.get_data()
        size = len(data) if data else 0
    if size > 0 and duration > 0:
        speed = size / duration / 1024
        size_kb = size / 1024
    else:
        speed = 0
        size_kb = 0
    if response.status_code in (200, 206):
        logger.info(
            f'{request.remote_addr} - {request.method} {request.path} - '
            f'Sending {size_kb:.2f} kB in {duration:.2f} seconds ({speed:.2f} KB/s)'
        )
    elif response.status_code == 301:
        logger.info(
            f'{request.remote_addr} - {request.method} {request.path} - '
            f'Redirecting to {response.headers.get("Location")}'
        )
    else:
        logger.warning(f'{request.remote_addr} - {request.method} {request.path} - {response.status_code}')
    return response


@app.route('/')
def index():
    """Basic health check endpoint."""
    return 'Hentai@Home Python Client', {'Content-Type': 'text/plain'}


@app.route('/favicon.ico')
def favicon():
    """Redirect to E-Hentai favicon."""
    return redirect('https://e-hentai.org/favicon.ico', code=301)


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return "File not found", 404, {'Content-Type': 'text/plain'}


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return "Internal Server Error", 500, {'Content-Type': 'text/plain'}


def create_app():
    """Create and configure the Flask application."""
    if not load_from_config_file():
        logger.error('Failed to initialize configuration')
        sys.exit(1)

    hath_config = get_config()
    if not hath_config.client_id or not hath_config.client_key:
        logger.error('Client ID or Client Key not set in configuration')
        sys.exit(1)

    if hath_config.server.get('disable_logging', False):
        log_level = logging.WARNING
    else:
        log_level = logging.DEBUG

    setup_file_logging(hath_config.log_dir if hath_config.log_dir else 'log', log_level)
    start_metrics_flusher(include_gauges=False)
    logger.info('Hentai@Home Python Client initialized')

    return app


from hath.http import files as _files  # noqa: E402,F401
from hath.http import servercmd as _servercmd  # noqa: E402,F401
from hath.http import status as _status  # noqa: E402,F401
