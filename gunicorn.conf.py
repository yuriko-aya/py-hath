import gunicorn
import logging
import ssl
import sys

gunicorn.SERVER = 'Genetic Lifeform and Distributed Open Server 0.1-py '

# Workers
workers = 4
worker_class = "gevent"

# Connections
timeout = 30
keepalive = 0

# Restart workers after a certain number of requests
max_requests = 1000
max_requests_jitter = 100

# Logging
accesslog = "log/gunicorn_access.log"
errorlog = "log/gunicorn_error.log"
loglevel = "info"

# SSL/TLS
ciphers = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"

# Custom SSL Error Filter
class SSLErrorFilter(logging.Filter):
    def filter(self, record):
        if hasattr(record, 'exc_info') and record.exc_info:
            exc_type, exc_value, exc_traceback = record.exc_info
            if exc_type and issubclass(exc_type, ssl.SSLEOFError):
                record.levelno = logging.INFO
                record.levelname = 'INFO'
                record.msg = f"Client disconnected: {exc_value}"
                record.exc_info = None
                return True
        return True

# Apply filter to Gunicorn loggers
def post_worker_init(worker):
    ssl_filter = SSLErrorFilter()
    
    # Get the actual logger instances and add the filter
    gunicorn_logger = logging.getLogger('gunicorn.error')
    gunicorn_access_logger = logging.getLogger('gunicorn.access')
    
    # Add filter to both loggers
    gunicorn_logger.addFilter(ssl_filter)
    gunicorn_access_logger.addFilter(ssl_filter)
    
    # Custom exception handler
    def ssl_excepthook(exc_type, exc_value, exc_traceback):
        if exc_type and issubclass(exc_type, ssl.SSLEOFError):
            gunicorn_logger.info(f"SSL EOF handled in worker {worker.pid}")
        else:
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
    
    sys.excepthook = ssl_excepthook