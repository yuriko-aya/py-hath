"""Tests for the Unix-socket stats aggregator."""

from __future__ import annotations

import os
import threading
import time

import hath.metrics as metrics
from hath.stats_client import get_dashboard, get_history, get_metrics, get_status, post_stats, wait_for_socket
from hath.dashboard import render_dashboard_html
from hath.stats_server import (
    HISTORY_MAXLEN,
    apply_deltas,
    compute_sample,
    empty_state,
    render_prometheus,
    reset_history,
    serve,
    take_sample,
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

    history = get_history(sock_path=sock)
    assert history is not None
    assert "samples" in history
    html = get_dashboard(sock_path=sock)
    assert html is not None
    assert b"<svg" in html
    time.sleep(0.05)
    try:
        os.unlink(sock)
    except OSError:
        pass


def test_compute_sample_rates_from_two_totals():
    previous = {
        "cache_hits": 10.0,
        "cache_misses": 2.0,
        "bytes_served": 1000.0,
        "rpc_requests": 4.0,
        "rpc_errors": 1.0,
        "rpc_total_latency_ms": 0.0,
        "download_galleries_completed": 0.0,
    }
    current = empty_state()
    current["cache_hits"] = 70
    current["cache_misses"] = 12
    current["bytes_served"] = 4000
    current["rpc_requests"] = 10
    current["rpc_errors"] = 1
    current["download_active"] = True
    sample = compute_sample(current, previous, now=120.0, prev_ts=60.0)
    assert sample["hits_per_min"] == 60.0
    assert sample["misses_per_min"] == 10.0
    assert sample["bytes_per_min"] == 3000.0
    assert sample["rpc_per_min"] == 6.0
    assert sample["rpc_errors_per_min"] == 0.0
    assert sample["hit_rate"] == round(60 / 70, 4)
    assert sample["download_active"] == 1


def test_take_sample_first_is_baseline_then_rates():
    import hath.stats_server as stats_server

    stats_server._state = empty_state()
    reset_history()
    stats_server._state["cache_hits"] = 5
    assert take_sample(now=100.0) is None
    stats_server._state["cache_hits"] = 25
    sample = take_sample(now=160.0)
    assert sample is not None
    assert sample["hits_per_min"] == 20.0
    assert history_len() == 1
    reset_history()


def history_len() -> int:
    import hath.stats_server as stats_server

    with stats_server._lock:
        return len(stats_server._history)


def test_history_ring_drops_past_maxlen():
    import hath.stats_server as stats_server

    reset_history()
    with stats_server._lock:
        for i in range(HISTORY_MAXLEN + 5):
            stats_server._history.append({"ts": i})
        samples = list(stats_server._history)
    assert len(samples) == HISTORY_MAXLEN
    assert samples[0]["ts"] == 5
    assert samples[-1]["ts"] == HISTORY_MAXLEN + 4
    reset_history()


def test_dashboard_html_contains_svg():
    html = render_dashboard_html(
        [{"ts": 1, "hits_per_min": 2, "bytes_per_min": 3, "rpc_per_min": 1, "hit_rate": 0.5, "download_active": 0}]
    )
    assert "<svg" in html
    assert "Cache hits / min" in html
