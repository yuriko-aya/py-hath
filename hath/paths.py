"""Path helpers resolved from config_manager.Config."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import config_manager


def _cfg() -> "config_manager.Config":
    import config_manager
    return config_manager.Config


def get_data_dir() -> str:
    return _cfg().data_dir or "data"


def get_cache_dir() -> str:
    return _cfg().cache_dir or "cache"


def get_download_dir() -> str:
    return _cfg().download_dir or "download"


def get_config_dir() -> str:
    return _cfg().config_dir or "config"


def get_db_path() -> str:
    return os.path.join(get_data_dir(), "pcache.db")


def get_config_cache_path() -> str:
    return os.path.join(get_config_dir(), "config.json")


def cache_file_path(file_id: str) -> str:
    l1dir = file_id[:2]
    l2dir = file_id[2:4]
    return os.path.join(get_cache_dir(), l1dir, l2dir, file_id)


def cache_range_dir(static_range: str) -> str:
    l1dir = static_range[:2]
    l2dir = static_range[2:4]
    return os.path.join(get_cache_dir(), l1dir, l2dir)
