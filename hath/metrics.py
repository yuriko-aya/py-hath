"""In-process metrics with batched flush to the stats aggregator."""

from __future__ import annotations

import atexit
import logging
import os
import threading
import time
from typing import Any

from hath.local import RLock
from hath.stats_client import post_stats
from hath.stats_server import COUNTER_KEYS

logger = logging.getLogger(__name__)

FLUSH_INTERVAL_SECONDS = 10.0

_lock = RLock()
_state: dict[str, Any] = {
    "cache_hits": 0,
    "cache_misses": 0,
    "bytes_served": 0,
    "rpc_requests": 0,
    "rpc_errors": 0,
    "rpc_total_latency_ms": 0.0,
    "download_active": False,
    "download_last_error": "",
    "download_galleries_completed": 0,
    "started_at": time.time(),
}
_last_flushed: dict[str, float] = {key: 0 for key in COUNTER_KEYS}
_flusher_started = False
_include_gauges = False
_stop = threading.Event()


def record_cache_hit(bytes_served: int = 0) -> None:
    with _lock:
        _state["cache_hits"] += 1
        _state["bytes_served"] += bytes_served


def record_cache_miss() -> None:
    with _lock:
        _state["cache_misses"] += 1


def record_rpc_request(latency_ms: float, *, error: bool = False) -> None:
    with _lock:
        _state["rpc_requests"] += 1
        _state["rpc_total_latency_ms"] += latency_ms
        if error:
            _state["rpc_errors"] += 1


def set_download_status(*, active: bool | None = None, last_error: str | None = None) -> None:
    with _lock:
        if active is not None:
            _state["download_active"] = active
        if last_error is not None:
            _state["download_last_error"] = last_error


def record_download_completed() -> None:
    with _lock:
        _state["download_galleries_completed"] += 1


def snapshot() -> dict[str, Any]:
    """Local in-process snapshot (not cluster-wide). Prefer the stats aggregator."""
    with _lock:
        data = dict(_state)
    hits = data["cache_hits"]
    misses = data["cache_misses"]
    total = hits + misses
    rpc_count = data["rpc_requests"]
    data["cache_hit_rate"] = round(hits / total, 4) if total else None
    data["rpc_avg_latency_ms"] = (
        round(data["rpc_total_latency_ms"] / rpc_count, 2) if rpc_count else None
    )
    data["uptime_seconds"] = int(time.time() - data["started_at"])
    return data


def build_flush_payload(*, include_gauges: bool | None = None) -> dict[str, Any]:
    send_gauges = _include_gauges if include_gauges is None else include_gauges
    with _lock:
        deltas: dict[str, float] = {}
        for key in COUNTER_KEYS:
            current = _state[key]
            last = _last_flushed.get(key, 0)
            delta = current - last
            if delta > 0:
                deltas[key] = delta
        payload: dict[str, Any] = {"pid": os.getpid(), "deltas": deltas}
        if send_gauges:
            payload["gauges"] = {
                "download_active": _state["download_active"],
                "download_last_error": _state["download_last_error"],
            }
        return payload


def mark_flushed(payload: dict[str, Any]) -> None:
    deltas = payload.get("deltas") or {}
    with _lock:
        for key, delta in deltas.items():
            if key in _last_flushed:
                _last_flushed[key] += delta


def flush_metrics(*, include_gauges: bool | None = None) -> bool:
    payload = build_flush_payload(include_gauges=include_gauges)
    deltas = payload.get("deltas") or {}
    if not deltas and "gauges" not in payload:
        return True
    if post_stats(payload):
        mark_flushed(payload)
        return True
    return False


def start_metrics_flusher(*, include_gauges: bool = False) -> None:
    global _flusher_started, _include_gauges
    _include_gauges = include_gauges
    if _flusher_started:
        return
    _flusher_started = True
    _stop.clear()

    def _loop() -> None:
        while not _stop.wait(FLUSH_INTERVAL_SECONDS):
            try:
                flush_metrics()
            except Exception as e:
                logger.debug("Metrics flush error: %s", e)

    thread = threading.Thread(target=_loop, name="hath-metrics-flush", daemon=True)
    thread.start()
    atexit.register(_flush_on_exit)
    logger.debug("Metrics flusher started (include_gauges=%s)", include_gauges)


def _flush_on_exit() -> None:
    _stop.set()
    try:
        flush_metrics()
    except Exception:
        pass
