"""In-process metrics for monitoring endpoints."""

from __future__ import annotations

import threading
import time
from typing import Any

_lock = threading.Lock()
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
