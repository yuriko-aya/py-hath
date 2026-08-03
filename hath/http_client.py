"""Shared HTTP session with connection pooling."""

from __future__ import annotations

from typing import Optional

import requests

from hath.constants import USER_AGENT
from hath.local import Local

_context_local = Local()


def get_request_headers() -> dict[str, str]:
    return {"User-Agent": USER_AGENT}


def get_session() -> requests.Session:
    if not hasattr(_context_local, "session"):
        session = requests.Session()
        session.headers.update(get_request_headers())
        _context_local.session = session
    return _context_local.session


def get(
    url: str,
    *,
    timeout: int = 10,
    proxies: Optional[dict[str, str]] = None,
    stream: bool = False,
) -> requests.Response:
    return get_session().get(url, timeout=timeout, proxies=proxies, stream=stream)


def close_session() -> None:
    if hasattr(_context_local, "session"):
        _context_local.session.close()
        delattr(_context_local, "session")
