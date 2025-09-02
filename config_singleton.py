"""
Configuration Singleton Module

This module provides a thread-safe singleton pattern for managing the HathConfig instance
across all modules, eliminating circular import issues.
"""
import threading
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class ConfigSingleton:
    """Thread-safe singleton for HathConfig instance."""
    
    _instance: Optional['ConfigSingleton'] = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._hath_config = None
                    cls._instance._initialized = False
        return cls._instance
    
    def initialize(self, hath_config) -> None:
        """Initialize with HathConfig instance."""
        with self._lock:
            self._hath_config = hath_config
            self._initialized = True
            logger.debug("Configuration singleton initialized")
            # Save configuration to cache for worker processes
            if hasattr(hath_config, 'save_config_cache'):
                hath_config.save_config_cache()
    
    def get_config(self):
        """Get the HathConfig instance."""
        # If not initialized, try to load from cache (for worker processes)
        if not self._initialized or self._hath_config is None:
            self._load_from_cache()
        return self._hath_config
    
    def _load_from_cache(self) -> None:
        """Load configuration from cache file (for worker processes)."""
        with self._lock:
            if self._initialized and self._hath_config is not None:
                return  # Already loaded by another thread
            
            try:
                from hath_config import HathConfig
                hath_config = HathConfig()
                
                # Try to load from cache first
                if hath_config.load_config_cache():
                    self._hath_config = hath_config
                    self._initialized = True
                    logger.debug("Configuration loaded from cache in worker process")
                else:
                    logger.warning("Failed to load configuration from cache")
                    
            except Exception as e:
                logger.error(f"Failed to load configuration from cache: {e}")
    
    def is_initialized(self) -> bool:
        """Check if configuration is initialized."""
        return self._initialized and self._hath_config is not None
    
    def reset(self) -> None:
        """Reset the configuration (useful for testing)."""
        with self._lock:
            self._hath_config = None
            self._initialized = False

# Global instance
config_manager = ConfigSingleton()

def get_hath_config():
    """Convenience function to get HathConfig instance."""
    return config_manager.get_config()

def initialize_config(hath_config) -> None:
    """Initialize the global configuration."""
    config_manager.initialize(hath_config)

def is_config_ready() -> bool:
    """Check if configuration is ready to use."""
    return config_manager.is_initialized()
