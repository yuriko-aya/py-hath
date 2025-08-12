"""
HTTP Bandwidth Monitor for throttling network traffic.

This module provides bandwidth throttling to ensure the client respects
server-imposed bandwidth limits and maintains good network citizenship.
"""

import threading
import time
from typing import Optional
from .settings import Settings
from .out import Out


class HTTPBandwidthMonitor:
    """Monitors and throttles HTTP bandwidth usage."""
    
    # Time resolution: 50 ticks per second (20ms per tick)
    TIME_RESOLUTION = 50
    
    # Window length for short-term throttling
    WINDOW_LENGTH = 5
    
    _instance = None
    _instance_lock = threading.RLock()
    
    def __new__(cls, *args, **kwargs):
        """Ensure singleton pattern."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    def get_instance(cls):
        """Get the singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def __init__(self):
        """Initialize the bandwidth monitor."""
        # Prevent multiple initialization
        if hasattr(self, '_initialized'):
            return
        
        self._lock = threading.RLock()
        
        # Calculate bytes per tick based on throttle setting
        throttle_bytes_per_sec = Settings.get_throttle_bytes_per_sec()
        self._bytes_per_tick = max(1, int(throttle_bytes_per_sec / self.TIME_RESOLUTION)) if throttle_bytes_per_sec > 0 else 0
        self._millis_per_tick = int(1000 / self.TIME_RESOLUTION)
        
        # Tracking arrays for each tick (50 ticks = 1 second)
        self._tick_bytes = [0] * self.TIME_RESOLUTION
        self._tick_seconds = [0] * self.TIME_RESOLUTION
        
        self._initialized = True
        Out.debug(f"HTTPBandwidthMonitor initialized: {throttle_bytes_per_sec} bytes/sec, {self._bytes_per_tick} bytes/tick")
    
    def wait_for_quota(self, byte_count: int):
        """Wait until bandwidth quota is available for the specified byte count.
        
        Args:
            byte_count: Number of bytes that will be transmitted
        """
        if self._bytes_per_tick <= 0:
            # No throttling configured
            return
        
        if byte_count <= 0:
            return
        
        with self._lock:
            while True:
                now = int(time.time() * 1000)  # Current time in milliseconds
                epoch_seconds = now // 1000
                current_tick = (now - epoch_seconds * 1000) // self._millis_per_tick
                current_second = int(epoch_seconds)
                
                bytes_this_tick = 0
                bytes_last_window = 0
                bytes_last_second = 0
                
                # Check bytes used in recent ticks
                for tick_offset in range(-self.TIME_RESOLUTION, current_tick + 1):
                    tick_index = tick_offset if tick_offset >= 0 else self.TIME_RESOLUTION + tick_offset
                    valid_second = current_second if tick_offset >= 0 else current_second - 1
                    
                    if self._tick_seconds[tick_index] == valid_second:
                        if tick_offset == current_tick:
                            bytes_this_tick += self._tick_bytes[tick_index]
                        else:
                            if tick_offset >= current_tick - self.WINDOW_LENGTH:
                                bytes_last_window += self._tick_bytes[tick_index]
                            
                            # Count bytes from approximately the last second (49/50ths)
                            bytes_last_second += self._tick_bytes[tick_index]
                
                # Check if we can send this amount
                if (bytes_this_tick + byte_count <= self._bytes_per_tick * 5 and
                    bytes_last_window + byte_count <= self._bytes_per_tick * 10 and
                    bytes_last_second + byte_count <= self._bytes_per_tick * self.TIME_RESOLUTION):
                    
                    # Record the usage
                    tick_index = current_tick
                    self._tick_bytes[tick_index] += byte_count
                    self._tick_seconds[tick_index] = current_second
                    break
                
                # Wait for next tick
                sleep_time = self._millis_per_tick / 1000.0
                time.sleep(sleep_time)
    
    def wait_for_quota_with_thread(self, thread: Optional[threading.Thread], byte_count: int):
        """Wait until bandwidth quota is available for the specified byte count.
        
        Args:
            thread: The thread requesting bandwidth (for sleep operations) 
            byte_count: Number of bytes that will be transmitted
        """
        # Just call the simpler version for now
        self.wait_for_quota(byte_count)
    
    def update_throttle_settings(self):
        """Update throttle settings from current configuration."""
        with self._lock:
            throttle_bytes_per_sec = Settings.get_throttle_bytes_per_sec()
            old_bytes_per_tick = self._bytes_per_tick
            
            self._bytes_per_tick = max(1, int(throttle_bytes_per_sec / self.TIME_RESOLUTION)) if throttle_bytes_per_sec > 0 else 0
            
            if old_bytes_per_tick != self._bytes_per_tick:
                Out.debug(f"Bandwidth throttle updated: {throttle_bytes_per_sec} bytes/sec, {self._bytes_per_tick} bytes/tick")
                
                # Clear history when throttle changes
                self._tick_bytes = [0] * self.TIME_RESOLUTION
                self._tick_seconds = [0] * self.TIME_RESOLUTION
    
    def get_usage_stats(self) -> dict:
        """Get current bandwidth usage statistics.
        
        Returns:
            Dictionary with current usage information
        """
        return self.get_current_usage()
    
    def get_current_usage(self) -> dict:
        """Get current bandwidth usage statistics.
        
        Returns:
            Dictionary with current usage information
        """
        with self._lock:
            now = int(time.time() * 1000)
            epoch_seconds = now // 1000
            current_tick = (now - epoch_seconds * 1000) // self._millis_per_tick
            current_second = int(epoch_seconds)
            
            bytes_this_second = 0
            bytes_last_window = 0
            
            for tick_offset in range(-self.TIME_RESOLUTION, current_tick + 1):
                tick_index = tick_offset if tick_offset >= 0 else self.TIME_RESOLUTION + tick_offset
                valid_second = current_second if tick_offset >= 0 else current_second - 1
                
                if self._tick_seconds[tick_index] == valid_second:
                    bytes_this_second += self._tick_bytes[tick_index]
                    
                    if tick_offset >= current_tick - self.WINDOW_LENGTH:
                        bytes_last_window += self._tick_bytes[tick_index]
            
            throttle_limit = Settings.get_throttle_bytes_per_sec()
            
            return {
                'bytes_this_second': bytes_this_second,
                'bytes_last_window': bytes_last_window,
                'bytes_per_tick_limit': self._bytes_per_tick,
                'throttle_limit_per_second': throttle_limit,
                'utilization_percent': (bytes_this_second / throttle_limit * 100) if throttle_limit > 0 else 0
            }
    
    def is_throttling_enabled(self) -> bool:
        """Check if bandwidth throttling is enabled.
        
        Returns:
            True if throttling is active
        """
        return self._bytes_per_tick > 0
    
    def throttle_bandwidth(self, byte_count: int):
        """Throttle bandwidth by waiting for quota (Java compatibility method).
        
        Args:
            byte_count: Number of bytes to throttle
        """
        self.wait_for_quota(byte_count)
