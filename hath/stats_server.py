"""Unix-socket HTTP aggregator for process-wide metrics."""

from __future__ import annotations

import json
import logging
import os
import shutil
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler
from typing import Any
from urllib.parse import urlparse

from hath.paths import get_cache_dir, get_stats_sock_path

logger = logging.getLogger(__name__)

COUNTER_KEYS = (
    "cache_hits",
    "cache_misses",
    "bytes_served",
    "rpc_requests",
    "rpc_errors",
    "rpc_total_latency_ms",
    "download_galleries_completed",
)

PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def empty_state() -> dict[str, Any]:
    return {
        "cache_hits": 0,
        "cache_misses": 0,
        "bytes_served": 0,
        "rpc_requests": 0,
        "rpc_errors": 0,
        "rpc_total_latency_ms": 0.0,
        "download_galleries_completed": 0,
        "download_active": False,
        "download_last_error": "",
        "started_at": time.time(),
    }


_state = empty_state()
_lock = threading.Lock()


def apply_deltas(state: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    """Merge a flush payload into aggregated state. Ignores negative deltas."""
    deltas = payload.get("deltas") or {}
    for key in COUNTER_KEYS:
        value = deltas.get(key, 0)
        try:
            numeric = float(value) if key == "rpc_total_latency_ms" else int(value)
        except (TypeError, ValueError):
            continue
        if numeric > 0:
            state[key] = state.get(key, 0) + numeric

    gauges = payload.get("gauges")
    if isinstance(gauges, dict):
        if "download_active" in gauges:
            state["download_active"] = bool(gauges["download_active"])
        if "download_last_error" in gauges:
            state["download_last_error"] = str(gauges["download_last_error"] or "")
    return state


def derive_fields(state: dict[str, Any]) -> dict[str, Any]:
    data = dict(state)
    hits = int(data.get("cache_hits") or 0)
    misses = int(data.get("cache_misses") or 0)
    total = hits + misses
    rpc_count = int(data.get("rpc_requests") or 0)
    data["cache_hit_rate"] = round(hits / total, 4) if total else None
    latency = float(data.get("rpc_total_latency_ms") or 0)
    data["rpc_avg_latency_ms"] = round(latency / rpc_count, 2) if rpc_count else None
    started = float(data.get("started_at") or time.time())
    data["uptime_seconds"] = int(time.time() - started)
    return data


def render_prometheus(state: dict[str, Any], extra_gauges: dict[str, float] | None = None) -> str:
    data = derive_fields(state)
    lines = [
        "# HELP hath_cache_hits_total Cache file hits",
        "# TYPE hath_cache_hits_total counter",
        f"hath_cache_hits_total {int(data['cache_hits'])}",
        "# HELP hath_cache_misses_total Cache file misses",
        "# TYPE hath_cache_misses_total counter",
        f"hath_cache_misses_total {int(data['cache_misses'])}",
        "# HELP hath_bytes_served_total Bytes served from cache hits",
        "# TYPE hath_bytes_served_total counter",
        f"hath_bytes_served_total {int(data['bytes_served'])}",
        "# HELP hath_rpc_requests_total RPC requests sent",
        "# TYPE hath_rpc_requests_total counter",
        f"hath_rpc_requests_total {int(data['rpc_requests'])}",
        "# HELP hath_rpc_errors_total RPC request errors",
        "# TYPE hath_rpc_errors_total counter",
        f"hath_rpc_errors_total {int(data['rpc_errors'])}",
        "# HELP hath_rpc_latency_milliseconds_total Cumulative RPC latency in milliseconds",
        "# TYPE hath_rpc_latency_milliseconds_total counter",
        f"hath_rpc_latency_milliseconds_total {float(data['rpc_total_latency_ms'])}",
        "# HELP hath_download_galleries_completed_total Galleries finished by the downloader",
        "# TYPE hath_download_galleries_completed_total counter",
        f"hath_download_galleries_completed_total {int(data['download_galleries_completed'])}",
        "# HELP hath_download_active Whether the download manager is running",
        "# TYPE hath_download_active gauge",
        f"hath_download_active {1 if data['download_active'] else 0}",
        "# HELP hath_uptime_seconds Stats aggregator uptime",
        "# TYPE hath_uptime_seconds gauge",
        f"hath_uptime_seconds {int(data['uptime_seconds'])}",
    ]
    for name, value in (extra_gauges or {}).items():
        lines.append(f"# TYPE {name} gauge")
        lines.append(f"{name} {value}")
    lines.append("")
    return "\n".join(lines)


def _cache_and_disk_gauges() -> tuple[dict[str, Any], dict[str, float]]:
    cache: dict[str, Any] = {}
    gauges: dict[str, float] = {}
    try:
        import db_manager

        cache = db_manager.get_cache_stats() or {}
        if cache.get("cache_count") is not None:
            gauges["hath_cache_files_total"] = float(cache["cache_count"])
        if cache.get("cache_size_bytes") is not None:
            gauges["hath_cache_size_bytes"] = float(cache["cache_size_bytes"])
        if cache.get("total_ranges") is not None:
            gauges["hath_cache_ranges_total"] = float(cache["total_ranges"])
    except Exception as e:
        logger.debug("Cache stats unavailable for metrics: %s", e)

    try:
        usage = shutil.disk_usage(get_cache_dir())
        gauges["hath_disk_free_bytes"] = float(usage.free)
    except Exception as e:
        logger.debug("Disk usage unavailable for metrics: %s", e)

    return cache, gauges


def snapshot_response() -> dict[str, Any]:
    with _lock:
        metrics = derive_fields(_state)
    cache, _gauges = _cache_and_disk_gauges()
    disk_free = None
    try:
        disk_free = shutil.disk_usage(get_cache_dir()).free
    except Exception:
        pass
    return {
        "status": "ok",
        "metrics": metrics,
        "download": {
            "active": metrics.get("download_active", False),
            "last_error": metrics.get("download_last_error", ""),
            "galleries_completed": metrics.get("download_galleries_completed", 0),
        },
        "cache": cache,
        "disk_free_bytes": disk_free,
    }


class StatsHandler(BaseHTTPRequestHandler):
    def address_string(self) -> str:
        return "unix"

    def log_message(self, fmt: str, *args: Any) -> None:
        logger.debug("%s - %s", self.address_string(), fmt % args)

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path != "/internal/stats":
            self._send(404, b"not found", "text/plain")
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("payload must be an object")
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
            self._send(400, str(e).encode(), "text/plain")
            return
        with _lock:
            apply_deltas(_state, payload)
        self._send(204, b"", "text/plain")

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/metrics":
            with _lock:
                state = dict(_state)
            _cache, extra = _cache_and_disk_gauges()
            body = render_prometheus(state, extra).encode("utf-8")
            self._send(200, body, PROMETHEUS_CONTENT_TYPE)
            return
        if path == "/status":
            body = json.dumps(snapshot_response()).encode("utf-8")
            self._send(200, body, "application/json")
            return
        self._send(404, b"not found", "text/plain")


class ThreadingUnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(sock_path: str | None = None) -> None:
    path = sock_path or get_stats_sock_path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if os.path.exists(path):
        os.unlink(path)
    server = ThreadingUnixHTTPServer(path, StatsHandler)
    os.chmod(path, 0o600)
    logger.info("Stats aggregator listening on %s", path)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        if os.path.exists(path):
            os.unlink(path)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    try:
        import config_manager

        config_manager.load_from_config_file()
    except Exception as e:
        logger.debug("Stats server continuing without config cache: %s", e)
    serve()


if __name__ == "__main__":
    main()
