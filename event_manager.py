import logging
import os
import time

from config_singleton import get_hath_config
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger(__name__)


class ConfigFileHandler(FileSystemEventHandler):
    """File system event handler for configuration cache file changes."""

    def __init__(self, config_file_path):
        super().__init__()
        self.config_file_path = str(config_file_path)
        self.config_filename = os.path.basename(self.config_file_path)
        logger.debug(f"Process {os.getpid()}: ConfigFileHandler initialized for: {self.config_file_path}")

    def on_modified(self, event):
        """Handle file modification events."""
        if event.is_directory:
            return
        
        # Check if this is our config file (by filename)
        if str(event.src_path).endswith(self.config_filename):            
            # Small delay to ensure file write is complete
            time.sleep(0.1)
            
            logger.info(f"Process {os.getpid()}: Configuration cache file modified: {event.src_path}")
            # Reload configuration and update logging level
            # This ensures all worker processes pick up new settings from /servercmd/refresh_settings
            update_logging_level_from_cache()

# Global variables for file monitoring
_config_observer = None
_config_file_handler = None

def start_config_file_monitor():
    """Start monitoring the configuration cache file for changes using watchdog."""
    global _config_observer, _config_file_handler

    if _config_observer and _config_observer.is_alive():
        logger.debug(f"Process {os.getpid()}: Configuration file monitor already running")
        return  # Already running

    try:
        config_dir = Path("data")
        config_file = config_dir / ".hath_config_cache.json"
        
        # Ensure the directory exists
        config_dir.mkdir(exist_ok=True)
        
        logger.debug(f"Process {os.getpid()}: Starting watchdog monitoring for: {config_file}")
        logger.debug(f"Process {os.getpid()}: Monitoring directory: {config_dir.absolute()}")
        logger.debug(f"Process {os.getpid()}: Config file exists: {config_file.exists()}")
        
        # Create the event handler
        _config_file_handler = ConfigFileHandler(config_file)

        # Create and start the observer
        _config_observer = Observer()
        _config_observer.schedule(_config_file_handler, str(config_dir), recursive=False)
        _config_observer.start()
        
        logger.info(f"Process {os.getpid()}: Started configuration file monitoring for {config_file}")
        
        # Verify the observer is running
        if _config_observer.is_alive():
            logger.debug(f"Process {os.getpid()}: Watchdog observer thread is running")
        else:
            logger.warning(f"Process {os.getpid()}: Watchdog observer thread failed to start")
        
    except Exception as e:
        logger.error(f"Process {os.getpid()}: Failed to start configuration file monitoring: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise

def stop_config_file_monitor():
    """Stop monitoring the configuration cache file."""
    global _config_observer, _config_file_handler

    if _config_observer and _config_observer.is_alive():
        try:
            _config_observer.stop()
            _config_observer.join(timeout=2)  # Reduced timeout to avoid hanging during shutdown
            logger.debug("Stopped configuration file monitoring")
        except Exception as e:
            # During shutdown, logging might not work properly, so we suppress errors
            try:
                logger.error(f"Error stopping configuration file monitoring: {e}")
            except:
                pass

    _config_observer = None
    _config_file_handler = None

def update_logging_level():
    """Update logging level based on hath_config settings."""
    hath_config = get_hath_config()
    if hath_config and hasattr(hath_config, 'config'):
        disable_logging = hath_config.config.get('disable_logging', '').lower()
        
        if disable_logging == 'true':
            # Set hath_client.log handler to WARNING level
            root_logger = logging.getLogger()
            for handler in root_logger.handlers:
                if isinstance(handler, logging.FileHandler) and 'hath_client.log' in handler.baseFilename:
                    handler.setLevel(logging.WARNING)
                    logging.info("Logging level for hath_client.log set to WARNING due to disable_logging=true")
                    break
        else:
            # Ensure normal DEBUG level logging
            root_logger = logging.getLogger()
            for handler in root_logger.handlers:
                if isinstance(handler, logging.FileHandler) and 'hath_client.log' in handler.baseFilename:
                    handler.setLevel(logging.DEBUG)
                    break

def update_logging_level_from_cache():
    """Update logging level and reload configuration by reloading from cache file."""
    from config_singleton import force_reload_config

    try:
        # Force reload configuration in the singleton
        logger.debug(f"Process {os.getpid()}: Reloading configuration from cache file...")
        success = force_reload_config()
        
        if not success:
            logger.warning("Failed to reload configuration from cache")
            return
        
        # Get the updated config
        hath_config = get_hath_config()
        if not hath_config:
            logger.warning("No configuration available after cache reload")
            return
        
        # Apply logging level changes
        update_logging_level()
        logger.info(f"Process {os.getpid()}: Configuration and logging level updated from cache")
        
        # Log some key config changes for verification
        host = hath_config.config.get('host', 'unknown')
        port = hath_config.config.get('port', 'unknown')
        disable_logging = hath_config.config.get('disable_logging', 'false')
        logger.debug(f"Updated config: host={host}, port={port}, disable_logging={disable_logging}")
        
    except Exception as e:
        logger.error(f"Error updating configuration and logging level from cache: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")