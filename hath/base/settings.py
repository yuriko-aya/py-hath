"""
Settings module for Hentai@Home Python Client.
Contains all configuration constants and settings management.
"""

import os
import re
import socket
from pathlib import Path
from typing import Optional, Dict, List


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
    def get_client_key(cls) -> str:
        """Get the client key."""
        return cls._client_key
    
    @classmethod
    def get_client_port(cls) -> int:
        """Get the client port."""
        return cls._client_port if cls._client_port > 0 else 0
    
    @classmethod
    def set_client_port(cls, port: int):
        """Set the client port."""
        cls._client_port = port
    
    @classmethod
    def get_server_time_delta(cls) -> int:
        """Get the server time delta."""
        return cls._server_time_delta
    
    @classmethod
    def set_server_time_delta(cls, delta: int):
        """Set the server time delta."""
        cls._server_time_delta = delta
    
    @classmethod
    def get_server_time(cls) -> int:
        """Get the current server time."""
        import time
        return int(time.time()) + cls._server_time_delta
    
    @classmethod
    def is_static_range(cls, file_id: str) -> bool:
        """Check if a file ID belongs to a static range."""
        if not file_id or len(file_id) < 2:
            return False
        static_range = file_id[:2]
        return static_range in cls._static_ranges
    
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
