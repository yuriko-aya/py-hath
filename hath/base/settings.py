"""
Settings module for Hentai@Home Python Client.
Contains all configuration constants and settings management.
"""

import os
import re
import socket
import time
from pathlib import Path
from typing import Optional, Dict, List

from .out import Out


class Settings:
    """Global settings and configuration for the Hentai@Home client."""
    
    # Constants
    NEWLINE = os.linesep
    CLIENT_BUILD = 176  # Latest build number (2025)
    CLIENT_KEY_LENGTH = 20
    MAX_KEY_TIME_DRIFT = 300
    MAX_CONNECTION_BASE = 20
    TCP_PACKET_SIZE = 1460
    
    CLIENT_VERSION = "1.6.4#py"  # Updated version identifier
    CLIENT_RPC_PROTOCOL = "http://"
    CLIENT_RPC_HOST = "rpc.hentaiathome.net"
    CLIENT_LOGIN_FILENAME = "client_login"
    CONTENT_TYPE_DEFAULT = "text/html; charset=iso-8859-1"
    
    # Instance variables
    _active_client = None
    _image_proxy = None
    _rpc_server_lock = object()
    _rpc_servers = None
    _rpc_server_current = None
    _rpc_server_last_failed = None
    _image_proxy_type = None
    _image_proxy_host = None
    _static_ranges: Dict[str, int] = {}
    
    # Server time synchronization
    _server_time_delta = 0
    
    # Directory paths
    _data_dir: Optional[Path] = None
    _log_dir: Optional[Path] = None
    _cache_dir: Optional[Path] = None
    _temp_dir: Optional[Path] = None
    _download_dir: Optional[Path] = None
    
    # Configuration variables
    _client_key = ""
    _client_host = ""
    _data_dir_path = "data"
    _log_dir_path = "log"
    _cache_dir_path = "cache"
    _temp_dir_path = "tmp"
    _download_dir_path = "download"
    _rpc_path = "15/rpc?"
    
    _rpc_server_port = 443
    _client_id = 0
    _client_port = 0
    _throttle_bytes = 0
    _override_conns = 0
    _server_time_delta = 0
    _max_allowed_file_size = 1073741824  # 1GB
    _current_static_range_count = 0
    _max_filename_length = 125
    _image_proxy_port = 0
    
    _disk_limit_bytes = 0
    _disk_remaining_bytes = 0
    _file_system_blocksize = 4096
    
    # Boolean flags
    _verify_cache = False
    _rescan_cache = False
    _skip_free_space_check = False
    _warn_new_client = False
    _use_less_memory = False
    _disable_bwm = False
    _disable_download_bwm = False
    _disable_file_verification = False
    _disable_logs = False
    _flush_logs = False
    _disable_ip_origin_check = False
    _disable_flood_control = False
    _debug_mode = False
    
    @classmethod
    def set_active_client(cls, client):
        """Set the active client instance."""
        cls._active_client = client
    
    @classmethod
    def get_active_client(cls):
        """Get the active client instance."""
        return cls._active_client
    
    @classmethod
    def login_credentials_are_syntax_valid(cls) -> bool:
        """Check if login credentials have valid syntax."""
        if cls._client_id is None:
            cls._client_id = 0
        if cls._client_key is None:
            cls._client_key = ""
        pattern = f"^[a-zA-Z0-9]{{{cls.CLIENT_KEY_LENGTH}}}$"
        return cls._client_id > 0 and re.match(pattern, cls._client_key) is not None
    
    @classmethod
    def load_client_login_from_file(cls) -> bool:
        """Load client login credentials from file."""
        client_login_file = cls.get_data_dir() / cls.CLIENT_LOGIN_FILENAME
        
        if not client_login_file.exists():
            return False
        
        try:
            file_content = client_login_file.read_text().strip()
            if file_content:
                parts = file_content.split("-", 1)
                if len(parts) == 2:
                    cls._client_id = int(parts[0])
                    cls._client_key = parts[1]
                    print(f"Loaded login settings from {cls.CLIENT_LOGIN_FILENAME}")
                    return True
        except Exception as e:
            print(f"Encountered error when reading {cls.CLIENT_LOGIN_FILENAME}: {e}")
        
        return False
    
    @classmethod
    def save_client_login_to_file(cls) -> bool:
        """Save client login credentials to file."""
        try:
            client_login_file = cls.get_data_dir() / cls.CLIENT_LOGIN_FILENAME
            content = f"{cls._client_id}-{cls._client_key}"
            client_login_file.write_text(content)
            return True
        except Exception as e:
            print(f"Failed to save login credentials: {e}")
            return False
    
    @classmethod
    def get_data_dir(cls) -> Path:
        """Get or create the data directory."""
        if cls._data_dir is None:
            cls._data_dir = Path(cls._data_dir_path)
        cls._data_dir.mkdir(exist_ok=True)
        return cls._data_dir
    
    @classmethod
    def get_log_dir(cls) -> Path:
        """Get or create the log directory."""
        if cls._log_dir is None:
            cls._log_dir = Path(cls._log_dir_path)
        cls._log_dir.mkdir(exist_ok=True)
        return cls._log_dir
    
    @classmethod
    def get_cache_dir(cls) -> Path:
        """Get or create the cache directory."""
        if cls._cache_dir is None:
            cls._cache_dir = Path(cls._cache_dir_path)
        cls._cache_dir.mkdir(exist_ok=True)
        return cls._cache_dir
    
    @classmethod
    def get_temp_dir(cls) -> Path:
        """Get or create the temporary directory."""
        if cls._temp_dir is None:
            cls._temp_dir = Path(cls._temp_dir_path)
        cls._temp_dir.mkdir(exist_ok=True)
        return cls._temp_dir
    
    @classmethod
    def get_download_dir(cls) -> Path:
        """Get or create the download directory."""
        if cls._download_dir is None:
            cls._download_dir = Path(cls._download_dir_path)
        cls._download_dir.mkdir(exist_ok=True)
        return cls._download_dir
    
    @classmethod
    def initialize_directories(cls):
        """Initialize all required directories."""
        cls.get_data_dir()
        cls.get_log_dir()
        cls.get_cache_dir()
        cls.get_temp_dir()
        cls.get_download_dir()
    
    @classmethod
    def parse_args(cls, args: List[str]):
        """Parse command line arguments."""
        for arg in args:
            if arg == "--disable-file-verification":
                cls._disable_file_verification = True
            elif arg == "--use-less-memory":
                cls._use_less_memory = True
            elif arg == "--rescan-cache":
                cls._rescan_cache = True
            elif arg == "--verify-cache":
                cls._verify_cache = True
            elif arg == "--disable-logs":
                cls._disable_logs = True
            elif arg == "--flush-logs":
                cls._flush_logs = True
            elif arg == "--debug" or arg == "--verbose":
                cls._debug_mode = True
            # Add more argument parsing as needed
    
    @classmethod
    def get_client_id(cls) -> int:
        """Get the client ID."""
        return cls._client_id
    
    @classmethod
    def getClientID(cls) -> int:
        """Get the client ID (Java compatibility method)."""
        return cls._client_id
    
    @classmethod
    def get_client_key(cls) -> str:
        """Get the client key."""
        return cls._client_key
    
    @classmethod
    def getClientKey(cls) -> str:
        """Get the client key (Java compatibility method)."""
        return cls._client_key
    
    @classmethod
    def getMaxAllowedFileSize(cls) -> int:
        """Get the maximum allowed file size (Java compatibility method)."""
        return cls.get_max_allowed_file_size()
    
    @classmethod
    def getTempDir(cls) -> Path:
        """Get the temp directory (Java compatibility method)."""
        return cls.get_temp_dir()
    
    @classmethod
    def getImageProxy(cls) -> Optional[str]:
        """Get the image proxy URL (Java compatibility method)."""
        if cls._image_proxy_host and cls._image_proxy_port:
            proxy_type = cls._image_proxy_type or "http"
            return f"{proxy_type}://{cls._image_proxy_host}:{cls._image_proxy_port}"
        return None
    
    @classmethod
    def get_client_port(cls) -> int:
        """Get the client port."""
        if cls._client_port is None:
            cls._client_port = 0
        return cls._client_port if cls._client_port > 0 else 0
    
    @classmethod
    def set_client_port(cls, port: int):
        """Set the client port."""
        cls._client_port = port
    
    @classmethod
    def get_server_time(cls) -> int:
        """Get the current server time."""
        return int(time.time()) + cls._server_time_delta
    
    @classmethod
    def is_static_range(cls, file_id: str) -> bool:
        """Check if a file ID belongs to a static range."""
        if not file_id or len(file_id) < 2:
            return False
        static_range = file_id[:2]
        # Check if any 4-character static range key starts with our 2-character range
        return any(key.startswith(static_range) for key in cls._static_ranges.keys())
    
    @classmethod
    def get_static_range_count(cls) -> int:
        """Get the number of static ranges."""
        return cls._current_static_range_count
    
    @classmethod
    def is_debug_mode(cls) -> bool:
        """Check if debug mode is enabled."""
        return cls._debug_mode
    
    @classmethod
    def is_disable_file_verification(cls) -> bool:
        """Check if file verification is disabled."""
        return cls._disable_file_verification
    
    @classmethod
    def get_disk_limit_bytes(cls) -> int:
        """Get the disk limit in bytes."""
        if cls._disk_limit_bytes is None:
            cls._disk_limit_bytes = 0
        return cls._disk_limit_bytes
    
    @classmethod
    def set_disk_limit_bytes(cls, limit: int):
        """Set the disk limit in bytes."""
        cls._disk_limit_bytes = limit
    
    @classmethod
    def get_max_allowed_file_size(cls) -> int:
        """Get the maximum allowed file size."""
        return cls._max_allowed_file_size
    
    @classmethod
    def get_throttle_bytes_per_sec(cls) -> int:
        """Get the bandwidth throttle in bytes per second."""
        return cls._throttle_bytes
    
    @classmethod
    def set_throttle_bytes_per_sec(cls, bytes_per_sec: int):
        """Set the bandwidth throttle in bytes per second."""
        cls._throttle_bytes = bytes_per_sec
    
    @classmethod
    def is_disable_bwm(cls) -> bool:
        """Check if bandwidth monitoring is disabled."""
        return cls._disable_bwm
    
    @classmethod
    def is_disable_download_bwm(cls) -> bool:
        """Check if download bandwidth monitoring is disabled."""
        return cls._disable_download_bwm
    
    @classmethod
    def get_image_proxy_host(cls) -> Optional[str]:
        """Get the image proxy host."""
        return cls._image_proxy_host
    
    @classmethod
    def get_image_proxy_port(cls) -> int:
        """Get the image proxy port."""
        return cls._image_proxy_port
    
    @classmethod
    def get_image_proxy_type(cls) -> Optional[str]:
        """Get the image proxy type."""
        return cls._image_proxy_type
    
    @classmethod
    def get_rpc_server_host(cls) -> Optional[str]:
        """Get the current RPC server host."""
        # For now, return the default RPC host
        # In a full implementation, this would manage a pool of RPC servers
        return cls.CLIENT_RPC_HOST
    
    @classmethod
    def mark_rpc_server_failure(cls, fail_host: str):
        """
        Mark an RPC server as failed.
        
        Args:
            fail_host: The hostname that failed
        """
        # Store the last failed server
        cls._rpc_server_last_failed = fail_host
        
        # In a full implementation, this would:
        # - Remove the server from the active pool temporarily
        # - Try alternative RPC servers if available
        # - Implement exponential backoff before retrying
        Out.debug(f"Settings: Marked RPC server {fail_host} as failed")
    
    @classmethod
    def get_server_time_delta(cls) -> int:
        """Get the server time delta in seconds."""
        return cls._server_time_delta
    
    @classmethod
    def set_server_time_delta(cls, delta: int):
        """Set the server time delta in seconds."""
        cls._server_time_delta = delta
    
    @classmethod
    def prompt_for_id_and_key(cls, input_handler):
        """Prompt user for client ID and key."""
        while not cls.login_credentials_are_syntax_valid():
            try:
                client_id_str = input_handler.query_string("Please enter your Client ID")
                if client_id_str:
                    cls._client_id = int(client_id_str)
                
                client_key = input_handler.query_string("Please enter your Client Key")
                if client_key:
                    cls._client_key = client_key.strip()
                
                if cls.login_credentials_are_syntax_valid():
                    cls.save_client_login_to_file()
                    break
                else:
                    print("Invalid credentials. Please try again.")
            except ValueError:
                print("Invalid Client ID. Please enter a number.")
            except Exception as e:
                print(f"Error: {e}")
    
    # Configuration utility methods
    @classmethod
    def get_bool(cls, key: str, default: bool = False) -> bool:
        """Get a boolean configuration value."""
        # This is a simplified implementation - in a real system, 
        # this would read from a configuration file or database
        config_map = {
            'validate_files_on_serve': True,  # Enable file validation by default
            'enable_bandwidth_throttling': True,
            'enable_session_management': True,
            'flush_logs': cls._flush_logs,
            'disable_logs': cls._disable_logs,
            'skip_free_space_check': False,
            'disable_download_bwm': cls._disable_download_bwm,
            'enable_gallery_downloader': True,
            'debug_mode': cls._debug_mode,
        }
        return config_map.get(key, default)
    
    @classmethod
    def get_int(cls, key: str, default: int = 0) -> int:
        """Get an integer configuration value."""
        config_map = {
            'disk_min_remaining_bytes': 1073741824,  # 1GB default
            'max_filename_length': 125,
            'rpc_server_port': cls._rpc_server_port
        }
        return config_map.get(key, default)
        """Get an integer configuration value."""
        # This is a simplified implementation - in a real system,
        # this would read from a configuration file or database
        config_map = {
            'max_connections': 100,
            'max_connections_per_ip': 10,
            'throttle_kbps': 0,  # 0 means no throttling
            'session_timeout': 300,  # 5 minutes
            'bandwidth_window_size': 20,  # 20 ticks window
            'validation_frequency_hours': 168,  # Validate once per week
        }
        return config_map.get(key, default)
    
    @classmethod
    def get_string(cls, key: str, default: str = "") -> str:
        """Get a string configuration value."""
        config_map = {
            'proxy_host': cls._image_proxy_host or "",
            'proxy_type': cls._image_proxy_type or "",
        }
        return config_map.get(key, default)
