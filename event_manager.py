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
    """Update logging level by reloading configuration from cache file."""
    hath_config = get_hath_config()
    if not hath_config:
        return
    
    try:
        # Reload configuration from cache file directly
        if hath_config.load_config_cache():
            # Apply logging level changes
            update_logging_level()
            logger.debug("Logging level updated from configuration cache")
        else:
            logger.debug("No configuration cache available for logging level update")
    except Exception as e:
        logger.error(f"Error updating logging level from cache: {e}")