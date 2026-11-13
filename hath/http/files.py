"""GET /h/... cache hit and cache-miss streaming."""

from __future__ import annotations

import logging
import mimetypes
import os
import shutil
from pathlib import Path

from flask import Response, send_file

from hath import cache, db
from hath.http.app import app
from hath.http.params import parse_additional_params
from hath.metrics import record_cache_hit, record_cache_miss
from hath.paths import cache_file_path
from hath.validation import file_id_hash_part
from hath.verification import verify_h_endpoint_auth

logger = logging.getLogger(__name__)


def _content_type_for(filename: str, file_id: str) -> str:
    if 'wbp' in filename or '-wbp' in file_id:
        return 'image/webp'
    content_type, _ = mimetypes.guess_type(filename)
    return content_type or 'application/octet-stream'


def _response_headers() -> dict:
    return {'Cache-Control': 'public, max-age=31536000'}


def _fetch_and_serve_remote(file_path: str, file_id: str, fileindex: str, xres: str,
                            static_name: str, filename: str, *, info_log: bool = False):
    """Download missing or invalid cache file and stream to client while caching."""
    record_cache_miss()
    success, file_resp = cache.fetch_remote_file(fileindex, xres, file_id)
    if not success or not file_resp:
        return "File not found", 404, {'Content-Type': 'text/plain'}

    content_type = _content_type_for(filename, file_id)
    if 'Content-Length' in file_resp.headers:
        file_size = int(file_resp.headers['Content-Length'])
    else:
        file_size = 0

    log_fn = logger.info if info_log else logger.debug
    if file_size:
        log_fn(f"Streaming {file_size / 1024:.2f} kB file: {file_id} as {content_type}")

    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    headers = _response_headers()
    if file_size:
        headers['Content-Length'] = str(file_size)

    return Response(
        cache.generate_and_cache(file_path, file_id, file_resp, file_size),
        mimetype=content_type,
        headers=headers,
    )


@app.route('/h/<file_id>/<additional>/<filename>')
def serve_file(file_id: str, additional: str, filename: str):
    """Serve cached files with authentication."""
    params = parse_additional_params(additional)

    keystamp = params.get('keystamp', '')
    fileindex = params.get('fileindex', '')
    xres = params.get('xres', '')

    if '-' not in keystamp:
        logger.warning(f"Invalid keystamp format: {keystamp}")
        return 'Invalid keystamp format', 400, {'Content-Type': 'text/plain'}

    try:
        keystamp_time, expected = keystamp.split('-', 1)
    except ValueError:
        logger.warning(f"Could not parse keystamp: {keystamp}")
        return 'Invalid keystamp format', 400, {'Content-Type': 'text/plain'}

    if not verify_h_endpoint_auth(keystamp_time, expected, file_id):
        logger.warning(f"Authentication failed for file: {file_id}")
        return "Forbidden", 403, {'Content-Type': 'text/plain'}

    if not fileindex:
        logger.warning(f"Missing fileindex for file: {file_id}")
        return "File not found", 404, {'Content-Type': 'text/plain'}

    try:
        int(fileindex)
    except ValueError:
        logger.warning(f"Invalid fileindex format: {fileindex}")
        return "File not found", 404, {'Content-Type': 'text/plain'}

    if xres != 'org' and not xres.isdigit():
        logger.warning(f"Invalid xres value: {xres}")
        return "File not found", 404, {'Content-Type': 'text/plain'}

    if len(file_id) < 2:
        logger.warning(f"File ID too short: {file_id}")
        return "File not found", 404, {'Content-Type': 'text/plain'}

    if file_id_hash_part(file_id) is None:
        logger.warning(f"Invalid SHA-1 in file_id: {file_id}")
        return "File not found", 404, {'Content-Type': 'text/plain'}

    static_name = file_id[:4]
    file_path = cache_file_path(file_id)
    content_type = _content_type_for(filename, file_id)

    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        logger.debug(f"File not found locally: {file_path}, attempting remote fetch...")
        if os.path.exists(file_path) and os.path.isdir(file_path):
            shutil.rmtree(file_path)
        return _fetch_and_serve_remote(
            file_path, file_id, fileindex, xres, static_name, filename,
        )

    try:
        file_size = Path(file_path).stat().st_size
        logger.info(f"Serving {file_size / 1024:.2f} kB file: {file_path} as {content_type}")
        db.update_last_access(static_name)
        record_cache_hit(file_size)
        return send_file(
            file_path,
            mimetype=content_type,
            conditional=True,
            max_age=31536000,
        )
    except Exception as e:
        logger.error(f"Error serving file {file_path}: {e}")
        return 'File serving failed', 500, {'Content-Type': 'text/plain'}
