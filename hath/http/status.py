"""Health and authenticated stats proxies."""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone

from cryptography import x509
from flask import Response, jsonify

from hath import db, storage
from hath.config import get_config
from hath.http.app import app
from hath.paths import get_cert_path, get_key_path
from hath.stats_client import get_dashboard, get_history, get_metrics, get_status
from hath.stats_server import PROMETHEUS_CONTENT_TYPE

logger = logging.getLogger(__name__)


def _status_actkey_ok(actkey: str) -> bool:
    hath_config = get_config()
    if not hath_config.client_id or not hath_config.client_key:
        return False
    expected = hashlib.sha1(f'hentai@home-status-{hath_config.client_id}'.encode()).hexdigest()
    return bool(actkey) and actkey == expected


@app.route('/health')
def health():
    """Readiness probe with DB, disk, and certificate checks."""
    checks = {
        'database': bool(db.get_cache_stats() is not None),
        'disk': storage.is_disk_ok(),
    }

    cert_ok = False
    cert_expires = None
    cert_path = get_cert_path()
    key_path = get_key_path()
    if os.path.exists(cert_path) and os.path.exists(key_path):
        try:
            with open(cert_path, 'rb') as f:
                cert = x509.load_pem_x509_certificate(f.read())
            cert_expires = cert.not_valid_after_utc.isoformat()
            cert_ok = cert.not_valid_after_utc > datetime.now(timezone.utc)
        except Exception as e:
            logger.warning(f"Certificate health check failed: {e}")
    checks['certificate'] = cert_ok

    healthy = all(checks.values())
    return jsonify({
        'status': 'ok' if healthy else 'degraded',
        'checks': checks,
        'certificate_expires': cert_expires,
    }), 200 if healthy else 503


@app.route('/status/<actkey>')
def status(actkey: str):
    """Authenticated snapshot from the stats aggregator."""
    if not _status_actkey_ok(actkey):
        hath_config = get_config()
        if not hath_config.client_id:
            logger.error("Missing hath_config, client_id or client_key for status")
            return 'Internal Server Error', 500, {'Content-Type': 'text/plain'}
        return "Forbidden", 403, {'Content-Type': 'text/plain'}

    try:
        data = get_status()
        if data is None:
            return jsonify({"status": "error", "message": "stats aggregator unavailable"}), 503
        return jsonify(data)
    except Exception as e:
        logger.error(f"Error fetching cache status: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/metrics/<actkey>')
def metrics_proxy(actkey: str):
    """Authenticated Prometheus text from the stats aggregator."""
    if not _status_actkey_ok(actkey):
        return "Forbidden", 403, {'Content-Type': 'text/plain'}
    body = get_metrics()
    if body is None:
        return "stats aggregator unavailable", 503, {'Content-Type': 'text/plain'}
    return Response(body, mimetype=PROMETHEUS_CONTENT_TYPE)


@app.route('/dashboard/<actkey>')
def dashboard_proxy(actkey: str):
    """Authenticated 24h SVG dashboard from the stats aggregator."""
    if not _status_actkey_ok(actkey):
        return "Forbidden", 403, {'Content-Type': 'text/plain'}
    body = get_dashboard()
    if body is None:
        return "stats aggregator unavailable", 503, {'Content-Type': 'text/plain'}
    return Response(body, mimetype='text/html')


@app.route('/history/<actkey>')
def history_proxy(actkey: str):
    """Authenticated 24h sample JSON from the stats aggregator."""
    if not _status_actkey_ok(actkey):
        return "Forbidden", 403, {'Content-Type': 'text/plain'}
    data = get_history()
    if data is None:
        return jsonify({"status": "error", "message": "stats aggregator unavailable"}), 503
    return jsonify(data)
