"""Shared constants for the H@H Python client."""

CLIENT_VERSION = "0.4.0"
CLIENT_BUILD = "176"

USER_AGENT = f"Hentai@Home Python Client {CLIENT_VERSION}"

VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
MIN_PORT = 1
MAX_PORT = 65535
MAX_WORKERS = 64
