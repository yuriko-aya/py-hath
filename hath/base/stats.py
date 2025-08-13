"""
Statistics tracking for the Hentai@Home client.

This module provides centralized statistics tracking for monitoring
client performance, cache status, and network activity.
"""

import threading
import time
from typing import List, Dict, Optional, Any

from .stat_listener import StatListener
from .settings import Settings
from .out import Out


class Stats:
    """Centralized statistics tracking for the H@H client."""
    
    _instance = None
    _lock = threading.RLock()
    _stat_listeners: List[StatListener] = []
    
    # Client status
    _client_running = False
    _client_suspended = False
    _program_status = "Stopped"
    _client_start_time = 0
    _last_server_contact = 0
    
    # Transfer statistics
    _files_sent = 0
    _files_received = 0
    _bytes_sent = 0
    _bytes_received = 0
    
    # Cache statistics
    _cache_count = 0
    _cache_size = 0
    
    # Connection statistics
    _open_connections = 0
    _max_connections = 0
    
    # Performance history (bytes sent per 10-second interval)
    _bytes_sent_history: Optional[List[int]] = None
    _bytes_sent_history_index = 0
    
    def __new__(cls):
        """Ensure singleton pattern."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    def get_instance(cls):
        """Get the singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def get_stats(self) -> Dict[str, Any]:
        """Get all statistics as a dictionary (instance method)."""
        return self.__class__.get_all_stats()
    
    def increment_files_sent(self):
        """Increment files sent counter (instance method)."""
        self.__class__.file_sent()
    
    def increment_files_received(self):
        """Increment files received counter (instance method)."""
        self.__class__.file_received()
    
    @classmethod
    def reset_stats(cls):
        """Reset all statistics to initial values."""
        with cls._lock:
            cls._client_running = False
            cls._client_suspended = False
            cls._program_status = "Stopped"
            cls._client_start_time = 0
            cls._last_server_contact = 0
            cls._files_sent = 0
            cls._files_received = 0
            cls._bytes_sent = 0
            cls._bytes_received = 0
            cls._cache_count = 0
            cls._cache_size = 0
            cls._open_connections = 0
            cls._max_connections = 0
            cls._bytes_sent_history = None
            cls._bytes_sent_history_index = 0
    
    @classmethod
    def track_bytes_sent_history(cls):
        """Enable bytes sent history tracking (361 intervals of 10 seconds each)."""
        with cls._lock:
            cls._bytes_sent_history = [0] * 361
            cls._bytes_sent_history_index = 0
    
    @classmethod
    def add_stat_listener(cls, listener: StatListener):
        """Add a statistics listener.
        
        Args:
            listener: The listener to add
        """
        with cls._lock:
            if listener not in cls._stat_listeners:
                cls._stat_listeners.append(listener)
    
    @classmethod
    def remove_stat_listener(cls, listener: StatListener):
        """Remove a statistics listener.
        
        Args:
            listener: The listener to remove
        """
        with cls._lock:
            if listener in cls._stat_listeners:
                cls._stat_listeners.remove(listener)
    
    @classmethod
    def _stat_changed(cls, stat_name: str):
        """Notify listeners that a statistic has changed.
        
        Args:
            stat_name: Name of the statistic that changed
        """
        client = Settings.get_active_client()
        announce = True
        
        if client and client.is_shutting_down():
            announce = False
        
        if announce:
            # Make a copy of listeners to avoid issues if list is modified during iteration
            listeners_copy = cls._stat_listeners.copy()
            for listener in listeners_copy:
                try:
                    listener.stat_changed(stat_name)
                except Exception as e:
                    # Don't let listener errors crash the stats system
                    Out.warning(f"Error in stat listener: {e}")
    
    # Status methods
    @classmethod
    def set_program_status(cls, new_status: str):
        """Set the program status.
        
        Args:
            new_status: New status description
        """
        with cls._lock:
            cls._program_status = new_status
            cls._stat_changed("programStatus")
    
    @classmethod
    def get_program_status(cls) -> str:
        """Get the current program status."""
        with cls._lock:
            return cls._program_status
    
    @classmethod
    def program_started(cls):
        """Mark the program as started."""
        with cls._lock:
            cls._client_running = True
            cls._client_start_time = int(time.time())
            cls._stat_changed("clientRunning")
            cls._stat_changed("clientStartTime")
    
    @classmethod
    def program_stopped(cls):
        """Mark the program as stopped."""
        with cls._lock:
            cls._client_running = False
            cls._stat_changed("clientRunning")
    
    @classmethod
    def set_client_suspended(cls, suspended: bool):
        """Set client suspension status.
        
        Args:
            suspended: True if client is suspended
        """
        with cls._lock:
            cls._client_suspended = suspended
            cls._stat_changed("clientSuspended")
    
    @classmethod
    def is_client_running(cls) -> bool:
        """Check if client is running."""
        with cls._lock:
            return cls._client_running
    
    @classmethod
    def is_client_suspended(cls) -> bool:
        """Check if client is suspended."""
        with cls._lock:
            return cls._client_suspended
    
    @classmethod
    def get_client_start_time(cls) -> int:
        """Get client start time as Unix timestamp."""
        with cls._lock:
            return cls._client_start_time
    
    # Transfer statistics
    @classmethod
    def file_sent(cls, bytes_count: int = 0):
        """Record a file being sent.
        
        Args:
            bytes_count: Number of bytes sent (optional)
        """
        with cls._lock:
            cls._files_sent += 1
            if bytes_count > 0:
                cls._bytes_sent += bytes_count
                cls._update_bytes_sent_history(bytes_count)
            cls._stat_changed("filesSent")
            if bytes_count > 0:
                cls._stat_changed("bytesSent")
    
    @classmethod
    def file_received(cls, bytes_count: int = 0):
        """Record a file being received.
        
        Args:
            bytes_count: Number of bytes received (optional)
        """
        with cls._lock:
            cls._files_received += 1
            if bytes_count > 0:
                cls._bytes_received += bytes_count
            cls._stat_changed("filesReceived")
            if bytes_count > 0:
                cls._stat_changed("bytesReceived")
    
    @classmethod
    def add_bytes_sent(cls, bytes_count: int):
        """Add to bytes sent counter.
        
        Args:
            bytes_count: Number of bytes to add
        """
        with cls._lock:
            cls._bytes_sent += bytes_count
            cls._update_bytes_sent_history(bytes_count)
            cls._stat_changed("bytesSent")
    
    @classmethod
    def add_bytes_received(cls, bytes_count: int):
        """Add to bytes received counter.
        
        Args:
            bytes_count: Number of bytes to add
        """
        with cls._lock:
            cls._bytes_received += bytes_count
            cls._stat_changed("bytesReceived")
    
    @classmethod
    def get_files_sent(cls) -> int:
        """Get number of files sent."""
        with cls._lock:
            return cls._files_sent
    
    @classmethod
    def get_files_received(cls) -> int:
        """Get number of files received."""
        with cls._lock:
            return cls._files_received
    
    @classmethod
    def get_bytes_sent(cls) -> int:
        """Get total bytes sent."""
        with cls._lock:
            return cls._bytes_sent
    
    @classmethod
    def get_bytes_received(cls) -> int:
        """Get total bytes received."""
        with cls._lock:
            return cls._bytes_received

    # Java compatibility methods for proxy and download code
    @classmethod
    def bytes_received(cls, n: int):
        """Java compatibility: increment bytes received."""
        cls.add_bytes_received(n)

    @classmethod
    def bytes_sent(cls, n: int):
        """Java compatibility: increment bytes sent."""
        cls.add_bytes_sent(n)
    
    # Java compatibility methods
    @classmethod
    def fileSent(cls):
        """Increment files sent counter (Java compatibility method)."""
        cls.file_sent()
    
    @classmethod
    def fileRcvd(cls):
        """Increment files received counter (Java compatibility method)."""
        cls.file_received()
    
    @classmethod
    def bytesSent(cls, count: int):
        """Add bytes sent (Java compatibility method)."""
        cls.bytes_sent(count)
    
    @classmethod
    def bytesRcvd(cls, count: int):
        """Add bytes received (Java compatibility method)."""
        cls.bytes_received(count)
    
    @classmethod
    def reset_bytes_sent_history(cls):
        """Reset the bytes sent history."""
        with cls._lock:
            if cls._bytes_sent_history:
                cls._bytes_sent_history = [0] * len(cls._bytes_sent_history)
                cls._bytes_sent_history_index = 0
    
    @classmethod
    def _update_bytes_sent_history(cls, bytes_count: int):
        """Update the bytes sent history.
        
        Args:
            bytes_count: Number of bytes to add to current interval
        """
        if cls._bytes_sent_history:
            current_time = int(time.time() / 10)  # 10-second intervals
            expected_index = current_time % len(cls._bytes_sent_history)
            
            if expected_index != cls._bytes_sent_history_index:
                # Clear intervals that we've skipped
                start_clear = (cls._bytes_sent_history_index + 1) % len(cls._bytes_sent_history)
                end_clear = expected_index
                
                if start_clear <= end_clear:
                    for i in range(start_clear, end_clear + 1):
                        cls._bytes_sent_history[i] = 0
                else:
                    for i in range(start_clear, len(cls._bytes_sent_history)):
                        cls._bytes_sent_history[i] = 0
                    for i in range(0, end_clear + 1):
                        cls._bytes_sent_history[i] = 0
                
                cls._bytes_sent_history_index = expected_index
            
            cls._bytes_sent_history[cls._bytes_sent_history_index] += bytes_count
    
    @classmethod
    def get_bytes_sent_history(cls) -> Optional[List[int]]:
        """Get bytes sent history array."""
        with cls._lock:
            if cls._bytes_sent_history:
                return cls._bytes_sent_history.copy()
            return None
    
    # Cache statistics
    @classmethod
    def set_cache_stats(cls, cache_count: int, cache_size: int):
        """Set cache statistics.
        
        Args:
            cache_count: Number of cached files
            cache_size: Total size of cached files in bytes
        """
        with cls._lock:
            old_count = cls._cache_count
            old_size = cls._cache_size
            cls._cache_count = cache_count
            cls._cache_size = cache_size
            
            if old_count != cache_count:
                cls._stat_changed("cacheCount")
            if old_size != cache_size:
                cls._stat_changed("cacheSize")
    
    @classmethod
    def get_cache_count(cls) -> int:
        """Get number of cached files."""
        with cls._lock:
            return cls._cache_count
    
    @classmethod
    def get_cache_size(cls) -> int:
        """Get total cache size in bytes."""
        with cls._lock:
            return cls._cache_size
    
    # Connection statistics
    @classmethod
    def set_open_connections(cls, count: int):
        """Set number of open connections.
        
        Args:
            count: Number of currently open connections
        """
        with cls._lock:
            cls._open_connections = count
            if count > cls._max_connections:
                cls._max_connections = count
                cls._stat_changed("maxConnections")
            cls._stat_changed("openConnections")
    
    @classmethod
    def get_open_connections(cls) -> int:
        """Get number of open connections."""
        with cls._lock:
            return cls._open_connections
    
    @classmethod
    def get_max_connections(cls) -> int:
        """Get maximum connections reached."""
        with cls._lock:
            return cls._max_connections
    
    # Server contact
    @classmethod
    def set_last_server_contact(cls, timestamp: int):
        """Set last server contact time.
        
        Args:
            timestamp: Unix timestamp of last server contact
        """
        with cls._lock:
            cls._last_server_contact = timestamp
            cls._stat_changed("lastServerContact")
    
    @classmethod
    def get_last_server_contact(cls) -> int:
        """Get last server contact time."""
        with cls._lock:
            return cls._last_server_contact
    
    @classmethod
    def server_contact(cls):
        """Record a successful server contact (used by CakeSphere)."""
        timestamp = int(time.time() * 1000)
        cls.set_last_server_contact(timestamp)
    
    # Utility methods
    @classmethod
    def get_all_stats(cls) -> Dict[str, Any]:
        """Get all statistics as a dictionary.
        
        Returns:
            Dictionary containing all current statistics
        """
        with cls._lock:
            return {
                'client_running': cls._client_running,
                'client_suspended': cls._client_suspended,
                'program_status': cls._program_status,
                'client_start_time': cls._client_start_time,
                'last_server_contact': cls._last_server_contact,
                'files_sent': cls._files_sent,
                'files_received': cls._files_received,
                'bytes_sent': cls._bytes_sent,
                'bytes_received': cls._bytes_received,
                'cache_count': cls._cache_count,
                'cache_size': cls._cache_size,
                'open_connections': cls._open_connections,
                'max_connections': cls._max_connections,
                'uptime_seconds': int(time.time()) - cls._client_start_time if cls._client_start_time > 0 else 0
            }
    
    @classmethod
    def get_transfer_rate_stats(cls) -> Dict[str, float]:
        """Get transfer rate statistics.
        
        Returns:
            Dictionary with current transfer rates
        """
        with cls._lock:
            uptime = int(time.time()) - cls._client_start_time if cls._client_start_time > 0 else 1
            
            return {
                'bytes_per_second_sent': cls._bytes_sent / uptime,
                'bytes_per_second_received': cls._bytes_received / uptime,
                'files_per_hour_sent': (cls._files_sent * 3600) / uptime,
                'files_per_hour_received': (cls._files_received * 3600) / uptime
            }
