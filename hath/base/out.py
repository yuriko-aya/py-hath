"""
Output and logging module for Hentai@Home Python Client.
Handles console output and file logging.
"""

import sys
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Optional


class Out:
    """Manages output and logging for the Hentai@Home client."""
    
    # Log levels
    DEBUG = 1
    INFO = 2
    WARNING = 4
    ERROR = 8
    
    LOGOUT = DEBUG | INFO | WARNING | ERROR
    LOGERR = WARNING | ERROR
    OUTPUT = INFO | WARNING | ERROR
    VERBOSE = ERROR
    
    _overridden = False
    _write_logs = True
    _suppressed_output = 0
    _logout_count = 0
    _logerr_count = 0
    _log_file_handler: Optional[logging.FileHandler] = None
    _logger: Optional[logging.Logger] = None
    _lock = threading.Lock()
    
    @classmethod
    def start_loggers(cls):
        """Initialize logging system."""
        from .settings import Settings
        
        if cls._logger is None:
            cls._logger = logging.getLogger('hath')
            cls._logger.setLevel(logging.DEBUG)
            
            # Console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_formatter = logging.Formatter(
                '%(asctime)s [%(levelname)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            console_handler.setFormatter(console_formatter)
            
            # Set console log level based on debug mode
            if Settings.is_debug_mode():
                console_handler.setLevel(logging.DEBUG)
            else:
                console_handler.setLevel(logging.INFO)
                
            cls._logger.addHandler(console_handler)
            
            # File handler
            if not Settings._disable_logs:
                try:
                    log_dir = Settings.get_log_dir()
                    log_file = log_dir / f"log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    
                    cls._log_file_handler = logging.FileHandler(log_file, encoding='utf-8')
                    file_formatter = logging.Formatter(
                        '%(asctime)s [%(levelname)s] %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S'
                    )
                    cls._log_file_handler.setFormatter(file_formatter)
                    cls._logger.addHandler(cls._log_file_handler)
                    
                    cls._write_logs = True
                except Exception as e:
                    print(f"Failed to initialize file logging: {e}")
                    cls._write_logs = False
    
    @classmethod
    def _log_message(cls, level: int, message: str):
        """Internal method to log a message."""
        if cls._logger is None:
            cls.start_loggers()
        
        with cls._lock:
            if cls._logger is not None:
                if level & cls.ERROR:
                    cls._logger.error(message)
                    cls._logerr_count += 1
                elif level & cls.WARNING:
                    cls._logger.warning(message)
                elif level & cls.INFO:
                    cls._logger.info(message)
                elif level & cls.DEBUG:
                    cls._logger.debug(message)
                
                cls._logout_count += 1
    
    @classmethod
    def debug(cls, message: str):
        """Log a debug message."""
        cls._log_message(cls.DEBUG, message)
    
    @classmethod
    def info(cls, message: str):
        """Log an info message."""
        cls._log_message(cls.INFO, message)
    
    @classmethod
    def warning(cls, message: str):
        """Log a warning message."""
        cls._log_message(cls.WARNING, message)
    
    @classmethod
    def error(cls, message: str):
        """Log an error message."""
        cls._log_message(cls.ERROR, message)
    
    @classmethod
    def flush_logs(cls):
        """Flush all log handlers."""
        if cls._logger:
            for handler in cls._logger.handlers:
                handler.flush()
    
    @classmethod
    def disable_logging(cls):
        """Disable logging."""
        if cls._logger:
            cls._logger.disabled = True
        cls._write_logs = False
    
    @classmethod
    def get_logout_count(cls) -> int:
        """Get the number of logged messages."""
        return cls._logout_count
    
    @classmethod
    def get_logerr_count(cls) -> int:
        """Get the number of error messages."""
        return cls._logerr_count
    
    @classmethod
    def setup_process_logging(cls, process_name: str):
        """Set up logging for a multiprocess worker."""
        if cls._logger is None:
            cls._logger = logging.getLogger(f'hath.{process_name}')
            cls._logger.setLevel(logging.DEBUG)
            
            # Console handler with process name
            console_handler = logging.StreamHandler(sys.stdout)
            console_formatter = logging.Formatter(
                f'%(asctime)s [{process_name}] [%(levelname)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            console_handler.setFormatter(console_formatter)
            
            # Set console level based on debug mode
            from .settings import Settings
            if Settings.get_bool('debug_mode', False):
                console_handler.setLevel(logging.DEBUG)
            else:
                console_handler.setLevel(logging.INFO)
            
            cls._logger.addHandler(console_handler)
            
            # File handler with process name in filename
            try:
                log_dir = Settings.get_log_dir()
                log_file = log_dir / f"log_{process_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                
                cls._log_file_handler = logging.FileHandler(log_file, encoding='utf-8')
                file_formatter = logging.Formatter(
                    f'%(asctime)s [{process_name}] [%(levelname)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
                cls._log_file_handler.setFormatter(file_formatter)
                cls._log_file_handler.setLevel(logging.DEBUG)
                cls._logger.addHandler(cls._log_file_handler)
                
            except Exception as e:
                print(f"Warning: Could not set up file logging for {process_name}: {e}")
        
        cls.info(f"Process {process_name} logging initialized")
