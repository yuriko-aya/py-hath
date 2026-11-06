"""Unix-socket HTTP aggregator for process-wide metrics."""

from __future__ import annotations

import json
import logging
import os
import shutil
import socketserver
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler
from typing import Any, Optional
from urllib.parse import urlparse

from hath.dashboard import render_dashboard_html
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
SAMPLE_INTERVAL_SECONDS = 60.0
HISTORY_MAXLEN = 1440


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
_history: deque[dict[str, Any]] = deque(maxlen=HISTORY_MAXLEN)
_last_sample_totals: Optional[dict[str, float]] = None
_last_sample_ts: Optional[float] = None
_sampler_stop = threading.Event()


def _counter_totals(state: dict[str, Any]) -> dict[str, float]:
    totals: dict[str, float] = {}
    for key in COUNTER_KEYS:
        value = state.get(key, 0)
        totals[key] = float(value or 0)
    return totals


def compute_sample(
    current: dict[str, Any],
    previous: dict[str, float],
    now: float,
    prev_ts: float,
    extra_gauges: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Build a per-minute rate sample from two cumulative snapshots."""
    elapsed = max(float(now) - float(prev_ts), 1e-9)
    scale = 60.0 / elapsed
    hits = max(0.0, float(current.get("cache_hits") or 0) - previous.get("cache_hits", 0))
    misses = max(0.0, float(current.get("cache_misses") or 0) - previous.get("cache_misses", 0))
    served = max(0.0, float(current.get("bytes_served") or 0) - previous.get("bytes_served", 0))
    rpc = max(0.0, float(current.get("rpc_requests") or 0) - previous.get("rpc_requests", 0))
    rpc_err = max(0.0, float(current.get("rpc_errors") or 0) - previous.get("rpc_errors", 0))
    galleries = max(
        0.0,
        float(current.get("download_galleries_completed") or 0)
        - previous.get("download_galleries_completed", 0),
    )
    total = hits + misses
    extra = extra_gauges or {}
    return {
        "ts": int(now),
        "hits_per_min": round(hits * scale, 2),
        "misses_per_min": round(misses * scale, 2),
        "bytes_per_min": round(served * scale, 2),
        "rpc_per_min": round(rpc * scale, 2),
        "rpc_errors_per_min": round(rpc_err * scale, 2),
        "galleries_per_min": round(galleries * scale, 2),
        "hit_rate": round(hits / total, 4) if total else None,
        "download_active": 1 if current.get("download_active") else 0,
        "cache_size_bytes": extra.get("hath_cache_size_bytes"),
        "disk_free_bytes": extra.get("hath_disk_free_bytes"),
    }


def take_sample(now: float | None = None) -> dict[str, Any] | None:
    """Append a history sample. First call only sets the baseline and returns None."""
    global _last_sample_totals, _last_sample_ts
    now_ts = time.time() if now is None else now
    with _lock:
        current_state = dict(_state)
    extra = {}
    try:
        _cache, extra = _cache_and_disk_gauges()
    except Exception:
        extra = {}
    totals = _counter_totals(current_state)
    if _last_sample_totals is None or _last_sample_ts is None:
        _last_sample_totals = totals
        _last_sample_ts = now_ts
        return None
    sample = compute_sample(current_state, _last_sample_totals, now_ts, _last_sample_ts, extra)
    _last_sample_totals = totals
    _last_sample_ts = now_ts
    with _lock:
        _history.append(sample)
    return sample


def history_samples() -> list[dict[str, Any]]:
    with _lock:
        return list(_history)


def reset_history() -> None:
    global _last_sample_totals, _last_sample_ts
    with _lock:
        _history.clear()
    _last_sample_totals = None
    _last_sample_ts = None


def start_history_sampler() -> None:
    _sampler_stop.clear()

    def _loop() -> None:
        take_sample()
        while not _sampler_stop.wait(SAMPLE_INTERVAL_SECONDS):
            try:
                take_sample()
            except Exception as e:
                logger.debug("History sample failed: %s", e)

    thread = threading.Thread(target=_loop, name="hath-stats-history", daemon=True)
    thread.start()


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
        if path == "/history":
            body = json.dumps({"samples": history_samples()}).encode("utf-8")
            self._send(200, body, "application/json")
            return
        if path == "/dashboard":
            html = render_dashboard_html(history_samples()).encode("utf-8")
            self._send(200, html, "text/html; charset=utf-8")
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
    start_history_sampler()
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
