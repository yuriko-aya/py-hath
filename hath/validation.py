"""Startup configuration validation."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from hath.constants import MAX_PORT, MAX_WORKERS, MIN_PORT, VALID_LOG_LEVELS

_PROXY_SCHEMES = frozenset({"http", "https", "socks4", "socks5"})
_SHA1_HEX_LENGTH = 40


def is_sha1_hex(value: str) -> bool:
    """Return True if value is a 40-character hexadecimal SHA-1 digest."""
    if len(value) != _SHA1_HEX_LENGTH:
        return False
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


def file_id_hash_part(file_id: str) -> str | None:
    """Extract the SHA-1 portion from a H@H file_id, or None if invalid."""
    hash_part = file_id.split('-', 1)[0] if '-' in file_id else file_id
    if is_sha1_hex(hash_part):
        return hash_part
    return None


def validate_proxy_url(proxy: str | None, name: str) -> list[str]:
    if proxy is None:
        return []
    parsed = urlparse(proxy)
    if parsed.scheme not in _PROXY_SCHEMES:
        return [f"{name} must use one of: {', '.join(sorted(_PROXY_SCHEMES))}"]
    if not parsed.hostname:
        return [f"{name} must include a host"]
    return []


def validate_startup_config(config: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    workers = config.get("workers", 4)
    if not isinstance(workers, int) or workers < 1 or workers > MAX_WORKERS:
        errors.append(f"workers must be an integer between 1 and {MAX_WORKERS}")

    if config.get("override_port"):
        port = config.get("hath_port")
        if port is None or not isinstance(port, int) or port < MIN_PORT or port > MAX_PORT:
            errors.append(f"hath_port must be an integer between {MIN_PORT} and {MAX_PORT}")

    log_level = config.get("log_level")
    if log_level is not None and str(log_level).upper() not in VALID_LOG_LEVELS:
        errors.append(f"log_level must be one of: {', '.join(sorted(VALID_LOG_LEVELS))}")

    for key in ("data_dir", "cache_dir", "log_dir", "config_dir"):
        value = config.get(key)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            errors.append(f"{key} must be a non-empty string")

    errors.extend(validate_proxy_url(config.get("download_proxy"), "download_proxy"))
    errors.extend(validate_proxy_url(config.get("rpc_proxy"), "rpc_proxy"))

    return errors
