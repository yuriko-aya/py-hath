"""Process-wide configuration singleton and RPC session helpers."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import socket
import time
from dataclasses import dataclass, field
from typing import List, Optional

import psutil

from hath.constants import CLIENT_BUILD
from hath.rpc_protocol import FatalStartupError, raise_if_fatal_login, rpc_url_path

logger = logging.getLogger(__name__)

_config: Optional["Config"] = None
_reloading = False


@dataclass
class Config:
    """Live client configuration. Server key/values live on ``server``."""

    data_dir: str = ""
    cache_dir: str = ""
    download_dir: str = ""
    config_dir: str = ""
    log_dir: str = ""
    override_port: bool = False
    hath_port: int = 443
    zip_downloaded: bool = True
    log_overrided: bool = False
    override_level: str = "DEBUG"
    is_server_ready: bool = False
    disable_ip_check: bool = False
    trust_x_forwarded_for: bool = False
    download_proxy: str = ""
    rpc_proxy: str = ""

    client_id: str = ""
    client_key: str = ""
    server_time: int = 0
    time_difference: int = 0
    server: dict = field(default_factory=dict)
    cert_file: str = ""
    key_file: str = ""
    client_build: str = CLIENT_BUILD

    rpc_server_ips: list = field(default_factory=list)
    rpc_fallback_domain: str = "rpc.hentaiathome.net"

    static_range_count: Optional[int] = None
    static_range: list = field(default_factory=list)

    verify_cache_requested: bool = False
    loaded_mtime: float = 0.0


def current_config() -> Config:
    """Return the singleton without reading config.json."""
    global _config
    if _config is None:
        _config = Config()
    return _config


def replace_config(cfg: Config | None = None) -> Config:
    """Swap the singleton. Tests pass a fresh ``Config`` to isolate state."""
    global _config
    _config = cfg if cfg is not None else Config()
    return _config


def get_config() -> Config:
    """Return the singleton, reloading safe fields when config.json is newer."""
    cfg = current_config()
    _maybe_reload(cfg)
    return cfg


def _maybe_reload(cfg: Config) -> None:
    global _reloading
    if _reloading or cfg.loaded_mtime <= 0:
        return
    from hath.paths import get_config_cache_path

    cache_file = get_config_cache_path()
    try:
        mtime = os.path.getmtime(cache_file)
    except OSError:
        return
    if mtime <= cfg.loaded_mtime:
        return
    _reloading = True
    try:
        with open(cache_file, "r") as f:
            data = json.load(f)
        _apply_safe_fields(cfg, data)
        cfg.loaded_mtime = mtime
        apply_hot_reload_settings()
        logger.info("Reloaded safe settings from %s", cache_file)
    except (OSError, json.JSONDecodeError) as e:
        logger.error(f"Error reloading config cache: {e}")
    finally:
        _reloading = False


def _apply_safe_fields(cfg: Config, data: dict) -> None:
    """Update fields that can change without a new listen port or certificate."""
    cfg.server = dict(data.get("config") or {})
    cfg.rpc_server_ips = list(data.get("rpc_server_ips") or [])
    cfg.static_range = list(data.get("static_range") or [])
    cfg.static_range_count = data.get("static_range_count", cfg.static_range_count)
    cfg.client_id = data.get("client_id", cfg.client_id)
    cfg.client_key = data.get("client_key", cfg.client_key)
    cfg.server_time = data.get("server_time", cfg.server_time)
    cfg.time_difference = data.get("time_difference", cfg.time_difference)


def _apply_full_file(cfg: Config, data: dict) -> None:
    cfg.data_dir = data.get("data_dir", "data")
    cfg.cache_dir = data.get("cache_dir", "cache")
    cfg.download_dir = data.get("download_dir", "download")
    cfg.config_dir = data.get("config_dir", "config")
    cfg.log_dir = data.get("log_dir", "log")
    cfg.override_port = data.get("override_port", False)
    cfg.hath_port = data.get("hath_port", 443)
    cfg.zip_downloaded = data.get("zip_downloaded", True)
    cfg.log_overrided = data.get("log_overrided", data.get("override_log", False))
    cfg.override_level = data.get("override_level", data.get("log_level", "DEBUG"))
    cfg.disable_ip_check = data.get("disable_ip_check", False)
    cfg.trust_x_forwarded_for = data.get("trust_x_forwarded_for", False)
    cfg.download_proxy = data.get("download_proxy") or ""
    cfg.rpc_proxy = data.get("rpc_proxy") or ""
    _apply_safe_fields(cfg, data)
    cfg.cert_file = os.path.join(cfg.data_dir, "client.crt")
    cfg.key_file = os.path.join(cfg.data_dir, "client.key")


def _mark_loaded(cfg: Config, cache_file: str) -> None:
    try:
        cfg.loaded_mtime = os.path.getmtime(cache_file)
    except OSError:
        cfg.loaded_mtime = time.time()


def is_verify_cache_requested() -> bool:
    """True when the server asked for cache validation on client_login."""
    return str(current_config().server.get("verify_cache", "")).lower() == "true"


def get_client_ip(environ: dict) -> str:
    """Resolve client IP for servercmd authorization."""
    cfg = current_config()
    if cfg.trust_x_forwarded_for:
        forwarded = environ.get("HTTP_X_FORWARDED_FOR")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return environ.get("REMOTE_ADDR", "unknown")


def get_local_ips():
    ips = []
    for ifname, addrs in psutil.net_if_addrs().items():
        if ifname == "lo":
            continue
        for a in addrs:
            if a.family in (socket.AF_INET, socket.AF_INET6):
                if a.address.startswith("127.") or a.address == "::1":
                    continue
                ips.append(a.address)
    return ips


def _convert_ipv6_mapped_to_ipv4(ip_list: List[str]) -> List[str]:
    """Convert IPv6-mapped IPv4 addresses to standard IPv4 format."""
    converted_ips = []

    for ip_str in ip_list:
        try:
            ip_addr = ipaddress.ip_address(ip_str)
            if ip_addr.version == 6 and ip_addr.ipv4_mapped:
                converted_ips.append(str(ip_addr.ipv4_mapped))
            elif ip_addr.version == 4:
                converted_ips.append(ip_str)
                logger.debug(f"Using IPv4 address: {ip_str}")
            else:
                converted_ips.append(ip_str)
                logger.warning(f"Regular IPv6 address detected: {ip_str}")
        except (ipaddress.AddressValueError, ValueError) as e:
            logger.error(f"Invalid IP address format: {ip_str}, skipping - {e}")
            continue
    logger.debug(f"RPC server IPs: {converted_ips}")
    return converted_ips


def read_client_credentials(data_dir) -> bool:
    """Read client_id and client_key from data/client_login file."""
    cfg = current_config()
    client_login_path = os.path.join(data_dir, "client_login")

    try:
        with open(client_login_path, "r") as f:
            content = f.read().strip()

        if "-" in content:
            client_id, client_key = content.split("-", 1)
            logger.info(f"Loaded client credentials: ID={client_id}")
            cfg.client_id = client_id
            cfg.client_key = client_key
            try:
                os.chmod(client_login_path, 0o600)
            except OSError:
                pass
            return True
        logger.error("Invalid format in client_login file. Expected 'id-key' format.")
        return False

    except FileNotFoundError:
        logger.warning(f"client_login file not found in {data_dir} directory")
        logger.info("Please enter your Hentai@Home client credentials:")

        try:
            client_id = input("Client ID: ").strip()
            client_key = input("Client Key: ").strip()

            if not client_id or not client_key:
                logger.error("Client ID and Client Key cannot be empty")
                return False

            try:
                int(client_id)
            except ValueError:
                logger.error("Client ID must be numeric")
                return False

            credentials_content = f"{client_id}-{client_key}"
            with open(client_login_path, "w") as f:
                f.write(credentials_content)
            os.chmod(client_login_path, 0o600)

            cfg.client_id = client_id
            cfg.client_key = client_key

            logger.info(f"Credentials saved to {client_login_path}")
            logger.info(f"Loaded client credentials: ID={client_id}")
            return True

        except KeyboardInterrupt:
            logger.error("User cancelled credential input")
            return False
        except Exception as e:
            logger.error(f"Error saving credentials: {e}")
            return False

    except Exception as e:
        logger.error(f"Error reading client credentials: {e}")
        return False


def get_server_time() -> bool:
    """Get server time from remote server."""
    from hath.rpc import call_rpc

    cfg = current_config()
    try:
        local_time_before = int(time.time())
        result = call_rpc("server_stat", timeout=10, retry_expired=False)
        if not result.ok:
            logger.error("Server did not return OK status for server_stat: %s", result.fail_code)
            return False

        for line in result.body_lines:
            if "=" in line:
                key, value = line.split("=", 1)
                if key.strip() == "server_time":
                    server_time = int(value.strip())
                    time_difference = server_time - local_time_before
                    cfg.server_time = server_time
                    logger.debug(f"Server time: {server_time}")
                    cfg.time_difference = time_difference
                    logger.debug(f"Time difference: {time_difference} seconds")
                    return True

        logger.error("server_time not found in response")
        return False

    except Exception as e:
        logger.error(f"Error getting server time: {e}")
        return False


def get_current_acttime() -> int:
    """Get current acttime (local time + time difference)."""
    current_local_time = int(time.time())
    return current_local_time + (current_config().time_difference or 0)


def generate_actkey(act: str, add: str = "", acttime: int | None = None) -> str:
    """Generate actkey for authentication."""
    cfg = current_config()
    current_acttime = get_current_acttime() if acttime is None else acttime
    data = f"hentai@home-{act}-{add}-{cfg.client_id}-{current_acttime}-{cfg.client_key}"
    return hashlib.sha1(data.encode()).hexdigest()


def rpc_path(act: str, add: str = "", endpoint: str = "rpc") -> str:
    """Build a signed API-16 RPC (or /dl) URL path."""
    cfg = current_config()
    current_acttime = get_current_acttime()
    actkey = generate_actkey(act, add, acttime=current_acttime)
    return rpc_url_path(
        act,
        add,
        endpoint=endpoint,
        client_build=cfg.client_build,
        client_id=cfg.client_id,
        acttime=current_acttime,
        actkey=actkey,
    )


def get_client_config(force_refresh=False) -> bool:
    """Get client configuration from remote server."""
    from hath.rpc import call_rpc

    cfg = current_config()
    try:
        act = "client_settings" if force_refresh else "client_login"
        result = call_rpc(act, timeout=10)
        if not result.ok:
            raise_if_fatal_login(result.fail_code or "")
            logger.error("Server did not return OK status: %s", result.fail_code)
            return False

        response_text = result.body_text

        if cfg.server.get("disable_logging") and "disable_logging" not in response_text:
            cfg.server.pop("disable_logging", None)

        for line in result.body_lines:
            if "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()

                if key == "rpc_server_ip":
                    if value:
                        raw_ips = [ip.strip() for ip in value.split(";") if ip.strip()]
                        cfg.rpc_server_ips = _convert_ipv6_mapped_to_ipv4(raw_ips)
                    else:
                        logger.warning("Empty rpc_server_ip received")

                if key == "static_ranges":
                    static_range = [sr for sr in value.split(";") if sr]
                    static_range_count = len(static_range)
                    cfg.static_range = static_range
                    cfg.static_range_count = static_range_count
                    logger.debug(f"Parsed {static_range_count} static ranges: {static_range}")

                if key == "static_range_count":
                    static_range_count = int(value)
                    cfg.static_range_count = static_range_count
                    logger.debug(f"Update static range count: {static_range_count}")

                cfg.server[key] = value

        host = cfg.server.get("host")
        local_ips = get_local_ips()
        if host not in local_ips:
            cfg.server["host"] = "0.0.0.0"

        logger.info("Client configuration loaded successfully")
        logger.debug(f"Host: {cfg.server.get('host')}")
        logger.debug(f"Port: {cfg.server.get('port')}")
        if cfg.rpc_server_ips:
            logger.debug(f"RPC servers: {cfg.rpc_server_ips}")

        if not force_refresh:
            cfg.verify_cache_requested = is_verify_cache_requested()
            if cfg.verify_cache_requested:
                logger.info("Server requested cache validation (verify_cache=true)")

        if force_refresh:
            apply_hot_reload_settings()

        save_config_cache()
        return True

    except FatalStartupError:
        raise
    except Exception as e:
        logger.error(f"Error getting client config: {e}")
        return False


def apply_hot_reload_settings() -> None:
    """Apply log level changes that do not need a process restart."""
    from hath.logging import set_file_log_level

    cfg = current_config()
    if cfg.log_overrided:
        level_name = cfg.override_level.upper()
    elif cfg.server.get("disable_logging"):
        level_name = "WARNING"
    else:
        return

    numeric_level = getattr(logging, level_name, None)
    if isinstance(numeric_level, int):
        logging.getLogger().setLevel(numeric_level)
        set_file_log_level(numeric_level)
        logger.info(f"Hot-reloaded log level to {level_name}")


def save_config_cache() -> bool:
    """Save current configuration to cache file for worker processes."""
    from hath.paths import get_config_cache_path, get_config_dir

    cfg = current_config()
    try:
        cache_file = get_config_cache_path()
        os.makedirs(get_config_dir(), exist_ok=True)

        cache_data = {
            "client_id": cfg.client_id,
            "client_key": cfg.client_key,
            "config": dict(cfg.server),
            "rpc_server_ips": list(cfg.rpc_server_ips),
            "static_range": list(cfg.static_range),
            "static_range_count": cfg.static_range_count,
            "server_time": cfg.server_time,
            "time_difference": cfg.time_difference,
            "cert_file": cfg.cert_file,
            "key_file": cfg.key_file,
            "timestamp": time.time(),
            "data_dir": cfg.data_dir,
            "cache_dir": cfg.cache_dir,
            "download_dir": cfg.download_dir,
            "config_dir": cfg.config_dir,
            "log_dir": cfg.log_dir,
            "log_overrided": cfg.log_overrided,
            "override_level": cfg.override_level,
            "disable_ip_check": cfg.disable_ip_check,
            "trust_x_forwarded_for": cfg.trust_x_forwarded_for,
            "download_proxy": cfg.download_proxy,
            "rpc_proxy": cfg.rpc_proxy,
        }

        with open(cache_file, "w") as f:
            json.dump(cache_data, f, indent=2)

        _mark_loaded(cfg, cache_file)
        logger.debug(f"Configuration cached to {cache_file}")
        return True

    except Exception as e:
        logger.error(f"Error saving config cache: {e}")
        return False


def initialize(base_config) -> bool:
    """Initialize the configuration by performing all required steps."""
    from hath.certs import get_ssl_certificate

    logger.debug("Initializing Hentai@Home client configuration...")
    cfg = current_config()

    cfg.data_dir = base_config.get("data_dir", "data")
    cfg.cache_dir = base_config.get("cache_dir", "cache")
    cfg.download_dir = base_config.get("download_dir", "download")
    cfg.config_dir = base_config.get("config_dir", "config")
    cfg.log_dir = base_config.get("log_dir", "log")
    cfg.override_port = base_config.get("override_port", False)
    cfg.hath_port = base_config.get("hath_port", 443)
    cfg.zip_downloaded = base_config.get("zip_downloaded", True)
    cfg.log_overrided = base_config.get("override_log", False)
    cfg.override_level = base_config.get("log_level", "DEBUG")
    cfg.disable_ip_check = base_config.get("disable_ip_check", False)
    cfg.trust_x_forwarded_for = base_config.get("trust_x_forwarded_for", False)
    cfg.download_proxy = base_config.get("download_proxy") or ""
    cfg.rpc_proxy = base_config.get("rpc_proxy") or ""

    if not read_client_credentials(cfg.data_dir):
        return False

    if not get_server_time():
        return False

    if not get_client_config():
        return False

    if not get_ssl_certificate():
        return False

    logger.debug("Configuration initialization completed successfully")
    return True


def load_from_config_file():
    from hath.paths import get_config_cache_path

    cfg = current_config()
    cache_file = get_config_cache_path()
    if not os.path.exists(cache_file):
        logger.error("Configuration cache file not found")
        return False

    with open(cache_file, "r") as f:
        try:
            config_data = json.load(f)
            _apply_full_file(cfg, config_data)
            _mark_loaded(cfg, cache_file)
            logger.info("Configuration loaded from cache file successfully")
            return True
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from config file: {e}")
            return False


def remove_config():
    """Remove the configuration cache file."""
    from hath.paths import get_config_cache_path

    cache_file = get_config_cache_path()
    try:
        if os.path.exists(cache_file):
            os.remove(cache_file)
            logger.debug("Configuration cache file removed")
        else:
            logger.debug("Configuration cache file does not exist, nothing to remove")
    except Exception as e:
        logger.error(f"Error removing config cache file: {e}")
    return True


def _get_rpc_host():
    """Get the RPC host to use - either from IP list or fallback domain."""
    cfg = current_config()
    if cfg.rpc_server_ips:
        return cfg.rpc_server_ips[0]
    return cfg.rpc_fallback_domain


def _handle_rpc_failure():
    """Handle RPC failure by moving the failed IP to the end of the list."""
    cfg = current_config()
    if cfg.rpc_server_ips and len(cfg.rpc_server_ips) > 1:
        failed_ip = cfg.rpc_server_ips.pop(0)
        cfg.rpc_server_ips.append(failed_ip)
        logger.debug(
            f"Moved failed RPC server {failed_ip} to end of list. Next server: {cfg.rpc_server_ips[0]}"
        )
