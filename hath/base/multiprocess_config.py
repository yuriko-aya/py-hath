"""
Multiprocess configuration for Hentai@Home client.
"""

from typing import Dict, Any


class MultiprocessConfig:
    """Configuration settings for multiprocess mode."""
    
    # Process settings
    HTTP_WORKERS = 4                    # Number of HTTP server processes
    DOWNLOAD_WORKERS = 2               # Number of download manager processes
    MAX_CONCURRENT_DOWNLOADS = 4      # Downloads per download manager
    
    # Queue settings
    STATS_QUEUE_SIZE = 1000           # Statistics queue buffer size
    DOWNLOAD_QUEUE_SIZE = 100         # Download request queue size
    COMMAND_QUEUE_SIZE = 50           # Command queue size
    RESPONSE_QUEUE_SIZE = 50          # Response queue size
    
    # Process monitoring
    HEARTBEAT_INTERVAL = 10           # Seconds between heartbeats
    HEALTH_CHECK_TIMEOUT = 60         # Seconds before considering process unhealthy
    RESTART_DELAY = 5                 # Seconds before restarting failed process
    MAX_RESTART_ATTEMPTS = 3          # Maximum restart attempts per process
    
    # Memory settings
    SHARED_MEMORY_SIZE = 1024 * 1024 * 1024  # 1GB shared memory
    CACHE_INDEX_MAX_SIZE = 100000     # Maximum entries in shared cache index
    
    # Performance settings
    STATS_BATCH_SIZE = 100            # Number of stats to batch before sending
    CACHE_SYNC_INTERVAL = 30          # Seconds between cache synchronization
    MAINTENANCE_INTERVAL = 30         # Seconds between maintenance tasks
    
    @classmethod
    def get_config(cls) -> Dict[str, Any]:
        """Get all configuration as dictionary."""
        return {
            'http_workers': cls.HTTP_WORKERS,
            'download_workers': cls.DOWNLOAD_WORKERS,
            'max_concurrent_downloads': cls.MAX_CONCURRENT_DOWNLOADS,
            'stats_queue_size': cls.STATS_QUEUE_SIZE,
            'download_queue_size': cls.DOWNLOAD_QUEUE_SIZE,
            'command_queue_size': cls.COMMAND_QUEUE_SIZE,
            'response_queue_size': cls.RESPONSE_QUEUE_SIZE,
            'heartbeat_interval': cls.HEARTBEAT_INTERVAL,
            'health_check_timeout': cls.HEALTH_CHECK_TIMEOUT,
            'restart_delay': cls.RESTART_DELAY,
            'max_restart_attempts': cls.MAX_RESTART_ATTEMPTS,
            'shared_memory_size': cls.SHARED_MEMORY_SIZE,
            'cache_index_max_size': cls.CACHE_INDEX_MAX_SIZE,
            'stats_batch_size': cls.STATS_BATCH_SIZE,
            'cache_sync_interval': cls.CACHE_SYNC_INTERVAL,
            'maintenance_interval': cls.MAINTENANCE_INTERVAL
        }
    
    @classmethod
    def apply_settings(cls, settings: Dict[str, Any]):
        """Apply settings from configuration."""
        cls.HTTP_WORKERS = settings.get('http_workers', cls.HTTP_WORKERS)
        cls.DOWNLOAD_WORKERS = settings.get('download_workers', cls.DOWNLOAD_WORKERS)
        cls.MAX_CONCURRENT_DOWNLOADS = settings.get('max_concurrent_downloads', cls.MAX_CONCURRENT_DOWNLOADS)
        cls.STATS_QUEUE_SIZE = settings.get('stats_queue_size', cls.STATS_QUEUE_SIZE)
        cls.DOWNLOAD_QUEUE_SIZE = settings.get('download_queue_size', cls.DOWNLOAD_QUEUE_SIZE)
        cls.COMMAND_QUEUE_SIZE = settings.get('command_queue_size', cls.COMMAND_QUEUE_SIZE)
        cls.RESPONSE_QUEUE_SIZE = settings.get('response_queue_size', cls.RESPONSE_QUEUE_SIZE)
        cls.HEARTBEAT_INTERVAL = settings.get('heartbeat_interval', cls.HEARTBEAT_INTERVAL)
        cls.HEALTH_CHECK_TIMEOUT = settings.get('health_check_timeout', cls.HEALTH_CHECK_TIMEOUT)
        cls.RESTART_DELAY = settings.get('restart_delay', cls.RESTART_DELAY)
        cls.MAX_RESTART_ATTEMPTS = settings.get('max_restart_attempts', cls.MAX_RESTART_ATTEMPTS)
        cls.SHARED_MEMORY_SIZE = settings.get('shared_memory_size', cls.SHARED_MEMORY_SIZE)
        cls.CACHE_INDEX_MAX_SIZE = settings.get('cache_index_max_size', cls.CACHE_INDEX_MAX_SIZE)
        cls.STATS_BATCH_SIZE = settings.get('stats_batch_size', cls.STATS_BATCH_SIZE)
        cls.CACHE_SYNC_INTERVAL = settings.get('cache_sync_interval', cls.CACHE_SYNC_INTERVAL)
        cls.MAINTENANCE_INTERVAL = settings.get('maintenance_interval', cls.MAINTENANCE_INTERVAL)


class ProcessType:
    """Process type constants."""
    MAIN = "main"
    HTTP_SERVER = "http_server"
    DOWNLOAD_MANAGER = "download_manager"
    STATS_COLLECTOR = "stats_collector"


class MessageType:
    """Message type constants for inter-process communication."""
    
    # Statistics messages
    HEARTBEAT = "heartbeat"
    FILE_SERVED = "file_served"
    FILE_RECEIVED = "file_received"
    DOWNLOAD_STATS = "download_stats"
    CACHE_UPDATE = "cache_update"
    
    # Command messages
    SHUTDOWN_REQUEST = "shutdown_request"
    RESTART_REQUEST = "restart_request"
    SETTINGS_REQUEST = "settings_request"
    SETTINGS_RESPONSE = "settings_response"
    CACHE_SYNC_REQUEST = "cache_sync_request"
    
    # Download messages
    GALLERY_DOWNLOAD = "gallery_download"
    PROXY_DOWNLOAD = "proxy_download"
    DOWNLOAD_COMPLETE = "download_complete"
    DOWNLOAD_FAILED = "download_failed"


class ProcessStatus:
    """Process status constants."""
    NOT_STARTED = "not_started"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"
    RESTARTING = "restarting"
