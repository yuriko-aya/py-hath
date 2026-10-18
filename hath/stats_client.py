"""HTTP client over the stats aggregator Unix socket."""

from __future__ import annotations

import http.client
import json
import logging
import os
import socket
import time
from typing import Any, Optional

from hath.paths import get_stats_sock_path

logger = logging.getLogger(__name__)


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, sock_path: str, timeout: float = 2.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self.unix_path = sock_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.unix_path)
        self.sock = sock


def request(
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    content_type: str | None = None,
    timeout: float = 2.0,
    sock_path: str | None = None,
) -> tuple[int, bytes, str]:
    path_name = sock_path or get_stats_sock_path()
    conn = UnixHTTPConnection(path_name, timeout=timeout)
    headers = {"Host": "localhost"}
    if content_type:
        headers["Content-Type"] = content_type
        headers["Content-Length"] = str(len(body or b""))
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        data = response.read()
        ctype = response.getheader("Content-Type") or ""
        return response.status, data, ctype
    finally:
        conn.close()


def post_stats(payload: dict[str, Any], *, sock_path: str | None = None) -> bool:
    raw = json.dumps(payload).encode("utf-8")
    try:
        status, _body, _ctype = request(
            "POST",
            "/internal/stats",
            body=raw,
            content_type="application/json",
            sock_path=sock_path,
        )
        return status in (200, 204)
    except OSError as e:
        logger.debug("Stats flush failed: %s", e)
        return False


def get_status(*, sock_path: str | None = None) -> Optional[dict[str, Any]]:
    try:
        status, body, _ctype = request("GET", "/status", sock_path=sock_path)
        if status != 200:
            return None
        data = json.loads(body.decode("utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.debug("Stats status fetch failed: %s", e)
        return None


def get_metrics(*, sock_path: str | None = None) -> Optional[bytes]:
    try:
        status, body, _ctype = request("GET", "/metrics", sock_path=sock_path)
        if status != 200:
            return None
        return body
    except OSError as e:
        logger.debug("Stats metrics fetch failed: %s", e)
        return None


def wait_for_socket(sock_path: str | None = None, timeout: float = 5.0) -> bool:
    path_name = sock_path or get_stats_sock_path()
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path_name):
            try:
                status, _body, _ctype = request("GET", "/status", sock_path=path_name)
                if status == 200:
                    return True
            except OSError:
                pass
        time.sleep(0.05)
    return False
