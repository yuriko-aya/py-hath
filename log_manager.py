import os
import logging

# Disable debug logging for noisy third-party libraries
# Temporarily enable watchdog debug logging to troubleshoot
logging.getLogger('watchdog').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('requests').setLevel(logging.WARNING)

# Create formatters
detailed_formatter = logging.Formatter(
    '%(asctime)s - [%(process)d] %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Create file handlers
def setup_file_logging(log_dir, file_level=logging.DEBUG):
    """Setup file-based logging handlers."""
    # Get root logger and clear any existing handlers
    root_logger = logging.getLogger()
    root_logger.handlers.clear()  # Remove any default handlers
    root_logger.setLevel(logging.DEBUG)

    # Main application log - no rotation (handled by system logrotate)
    app_handler = logging.FileHandler(
        filename=os.path.join(log_dir, 'hath_client.log'),
        encoding='utf-8'
    )
    app_handler.setFormatter(detailed_formatter)
    app_handler.setLevel(file_level)

    # Add handlers to root logger
    root_logger.addHandler(app_handler)
        
    # Also keep console output
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(detailed_formatter)
    console_handler.setLevel(logging.INFO)
    root_logger.addHandler(console_handler)
