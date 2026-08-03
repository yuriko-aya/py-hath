"""Tests for greenlet/thread-local storage helpers."""

from __future__ import annotations

import threading

from hath.local import Local, RLock


def test_local_isolates_threads():
    storage = Local()
    results: dict[str, int] = {}

    def worker(key: str, value: int) -> None:
        storage.value = value
        results[key] = storage.value

    t1 = threading.Thread(target=worker, args=("a", 1))
    t2 = threading.Thread(target=worker, args=("b", 2))
    t1.start()
    t2.start()
    t1.join(timeout=2)
    t2.join(timeout=2)
    assert results == {"a": 1, "b": 2}


def test_rlock_serializes_updates():
    count = 0
    lock = RLock()

    def increment() -> None:
        nonlocal count
        for _ in range(100):
            with lock:
                count += 1

    threads = [threading.Thread(target=increment) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert count == 400
