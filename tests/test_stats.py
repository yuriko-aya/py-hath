"""Tests for the Unix-socket stats aggregator."""

from __future__ import annotations

import os
import threading
import time

import hath.metrics as metrics
from hath.stats_client import get_metrics, get_status, post_stats, wait_for_socket
from hath.stats_server import (
    apply_deltas,
    empty_state,
    render_prometheus,
    serve,
)


def test_apply_deltas_ignores_negative_and_merges():
    state = empty_state()
    apply_deltas(state, {"deltas": {"cache_hits": 3, "cache_misses": -1, "bytes_served": 10}})
    apply_deltas(state, {"deltas": {"cache_hits": 2}})
    assert state["cache_hits"] == 5
    assert state["cache_misses"] == 0
    assert state["bytes_served"] == 10

    apply_deltas(state, {"gauges": {"download_active": True, "download_last_error": "boom"}})
    assert state["download_active"] is True
    assert state["download_last_error"] == "boom"


def test_render_prometheus_counters_and_gauges():
    state = empty_state()
    state["cache_hits"] = 4
    state["cache_misses"] = 1
    text = render_prometheus(state, {"hath_cache_files_total": 12})
    assert "# TYPE hath_cache_hits_total counter" in text
    assert "hath_cache_hits_total 4" in text
    assert "hath_cache_misses_total 1" in text
    assert "hath_download_active 0" in text
    assert "hath_cache_files_total 12" in text


def test_build_flush_payload_deltas_and_mark():
    metrics._state["cache_hits"] = 7
    metrics._last_flushed["cache_hits"] = 2
    payload = metrics.build_flush_payload(include_gauges=False)
    assert payload["deltas"]["cache_hits"] == 5
    assert "gauges" not in payload
    metrics.mark_flushed(payload)
    assert metrics._last_flushed["cache_hits"] == 7
    metrics._state["cache_hits"] = 0
    metrics._last_flushed["cache_hits"] = 0


def test_unix_socket_roundtrip(tmp_path):
    import hath.stats_server as stats_server

    stats_server._state = empty_state()
    sock = f"/tmp/hath-stats-{tmp_path.name[-8:]}.sock"
    thread = threading.Thread(target=serve, args=(sock,), daemon=True)
    thread.start()
    assert wait_for_socket(sock, timeout=5)

    assert post_stats(
        {"deltas": {"cache_hits": 9, "bytes_served": 100}},
        sock_path=sock,
    )
    assert post_stats(
        {"gauges": {"download_active": True, "download_last_error": ""}},
        sock_path=sock,
    )

    status = get_status(sock_path=sock)
    assert status is not None
    assert status["metrics"]["cache_hits"] == 9
    assert status["metrics"]["bytes_served"] == 100
    assert status["download"]["active"] is True

    body = get_metrics(sock_path=sock)
    assert body is not None
    text = body.decode("utf-8")
    assert "hath_cache_hits_total 9" in text
    assert "hath_download_active 1" in text
    time.sleep(0.05)
    try:
        os.unlink(sock)
    except OSError:
        pass
