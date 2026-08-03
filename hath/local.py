"""Greenlet/thread-local primitives for sync and gevent Gunicorn workers."""

from __future__ import annotations

try:
    from gevent.local import local as Local
except ImportError:
    from threading import local as Local

try:
    from gevent.lock import RLock
except ImportError:
    from threading import RLock

__all__ = ["Local", "RLock"]
