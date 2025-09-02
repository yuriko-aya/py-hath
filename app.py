import db_manager as db
import logging
import threading
import time
import socket
import hashlib
import random
import requests
import os
import mimetypes
import shutil
import signal
import sys
import atexit

from pathlib import Path

from concurrent.futures import ThreadPoolExecutor
from flask import Flask, g, jsonify, request, Response, request, send_file, redirect, url_for
from hath_config import HathConfig
from config_singleton import get_hath_config, initialize_config
from io import BytesIO
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configure logging
import logging.handlers
from datetime import datetime

# Disable debug logging for noisy third-party libraries
# Temporarily enable watchdog debug logging to troubleshoot
logging.getLogger('watchdog').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('requests').setLevel(logging.WARNING)

# Ensure log directory exists
log_dir = 'log'
os.makedirs(log_dir, exist_ok=True)

# Create formatters
detailed_formatter = logging.Formatter(
    '%(asctime)s - %(name)s [%(process)d] - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Create file handlers
def setup_file_logging():
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
    app_handler.setLevel(logging.DEBUG)
    
    # Add handlers to root logger
    root_logger.addHandler(app_handler)
        
    # Also keep console output
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(detailed_formatter)
    console_handler.setLevel(logging.INFO)
    root_logger.addHandler(console_handler)
    
    logging.debug("File logging initialized - logs will be stored in 'log' directory")
    logging.debug("Log files: hath_client.log")
    logging.debug("Log rotation is handled by system logrotate (multiprocess-safe)")

# Setup file logging
setup_file_logging()

logger = logging.getLogger(__name__)

app = Flask(__name__)

@app.before_request
def handle_double_slash_in_servercmd():
    """Handle the double slash case in servercmd URLs."""
    g.start_time = time.perf_counter()
    if request.path.startswith('/servercmd/') and '//' in request.path:
        # This specifically handles /servercmd/command//timestamp/key patterns
        # Replace // with / and internally redirect
        corrected_path = request.path.replace('//', '/')
        if corrected_path != request.path:
            # Extract path components
            parts = corrected_path.strip('/').split('/')
            if len(parts) >= 4 and parts[0] == 'servercmd':
                # Redirect to the route with defaults (no additional parameter)
                command, time_param, key = parts[1], parts[2], parts[3]
                # Generate new request to the proper endpoint
                from werkzeug.test import EnvironBuilder
                from werkzeug.wrappers import Request
                
                # Create a new request with the corrected path
                builder = EnvironBuilder(path=corrected_path, method=request.method)
                new_request = builder.get_request()
                
                # Call our servercmd function directly with empty additional
                return servercmd(command, '', time_param, key)

@app.after_request
def after_request(response):
    """Log the duration of the request."""
    duration = time.perf_counter() - g.start_time
    length = response.headers.get('Content-Length')
    if length is not None:
        size = int(length)
    else:
        # If not set, calculate the length of the response data (may not always be accurate for streamed responses)
        data = response.get_data()
        size = len(data) if data else 0
    if size > 0 and duration > 0:
        speed = size / duration / 1024
    else:
        speed = 0
    if response.status_code == 200:
        logger.info(f'{request.remote_addr} - {request.method} {request.path} - {size} bytes in {duration:.2f} seconds ({speed:.2f} KB/s)')
    else:
        logger.warning(f'{request.remote_addr} - {request.method} {request.path} - {response.status_code}')
    return response

@app.route('/')
def index():
    """Basic health check endpoint."""
    return 'Hentai@Home Client', {'Content-Type': 'text/plain'}

def parse_additional_params(additional: str) -> dict:
    """Parse additional parameters from key=value;key=value format."""
    params = {}
    if additional:
        for pair in additional.split(';'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                params[key.strip()] = value.strip()
    return params

@app.route('/h/<file_id>/<additional>/<filename>')
def serve_file(file_id: str, additional: str, filename: str):
    """Serve cached files with authentication."""
    # Parse additional parameters
    params = parse_additional_params(additional)
    
    keystamp = params.get('keystamp', '')
    fileindex = params.get('fileindex', '')
    xres = params.get('xres', '')
    
    # Extract expected hash from keystamp
    if '-' not in keystamp:
        logger.warning(f"Invalid keystamp format: {keystamp}")
        return 'Invalid keystamp format', 400, {'Content-Type': 'text/plain'}
    
    try:
        keystamp_time, expected = keystamp.split('-', 1)
    except ValueError:
        logger.warning(f"Could not parse keystamp: {keystamp}")
        return 'Invalid keystamp format', 400, {'Content-Type': 'text/plain'}
    
    # Verify authentication
    import verification_manager
    if not verification_manager.verify_h_endpoint_auth(keystamp_time, expected, file_id):
        logger.warning(f"Authentication failed for file: {file_id}")
        return "Forbidden", 403, {'Content-Type': 'text/plain'}
    
    # Validate fileindex
    if not fileindex:
        logger.warning(f"Missing fileindex for file: {file_id}")
        return "File not found", 404, {'Content-Type': 'text/plain'}
    
    try:
        fileindex_int = int(fileindex)
    except ValueError:
        logger.warning(f"Invalid fileindex format: {fileindex}")
        return "File not found", 404, {'Content-Type': 'text/plain'}
    
    # Validate xres
    if xres != 'org' and not xres.isdigit():
        logger.warning(f"Invalid xres value: {xres}")
        return "File not found", 404, {'Content-Type': 'text/plain'}
    
    # Check if file exists
    if len(file_id) < 2:
        logger.warning(f"File ID too short: {file_id}")
        return "File not found", 404, {'Content-Type': 'text/plain'}
    
    l1dir = file_id[:2]
    l2dir = file_id[2:4]
    file_path = os.path.join('cache', l1dir, l2dir, file_id)

    # Response headers
    response_headers = {
        'Cache-Control': 'public, max-age=31536000',
    }

    # Determine content type
    if 'wbp' in filename:
        content_type = 'image/webp'
    else:
        content_type, _ = mimetypes.guess_type(filename)
        if not content_type:
            content_type = 'application/octet-stream'

    def generate_and_cache(file_resp):
        with open(file_path, 'wb') as cache_file:
            for chunk in file_resp.iter_content(chunk_size=8192):
                if chunk:
                    cache_file.write(chunk)
                    yield chunk
        logger.debug(f"File cached at: {file_path}")

    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        logger.debug(f"File not found locally: {file_path}, attempting remote fetch...")
        if os.path.exists(file_path) and os.path.isdir(file_path):
            shutil.rmtree(file_path)
        # Prepare remote fetch URL
        import cache_manager
        success, file_resp = cache_manager.fetch_remote_file(fileindex, xres, file_id)
        if success:
            # Save to cache and stream to client simultaneously
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
           
            logger.debug(f"Streaming file: {file_id} as {content_type}")
            # Update last access time for cache tracking
            static_name = file_id[:4]
            db.update_last_access(static_name, new_file=True)
            return Response(
                generate_and_cache(file_resp),
                mimetype=content_type,
                headers=response_headers
            )
        else:
            return "File not found", 404, {'Content-Type': 'text/plain'}

    import cache_manager
    if not cache_manager.verify_file_integrity(file_path, file_id):
        os.remove(file_path)
        # Prepare remote fetch URL
        success, file_resp = cache_manager.fetch_remote_file(fileindex, xres, file_id)
        if success:
            # Save to cache and stream to client simultaneously
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            logger.debug(f"Streaming file: {file_id} as {content_type}")
            
            # Update last access time for cache tracking
            static_name = file_id[:4]
            db.update_last_access(static_name, new_file=True)
            
            return Response(
                generate_and_cache(file_resp),
                mimetype=content_type,
                headers=response_headers
            )
        else:
            return "File not found", 404, {'Content-Type': 'text/plain'}

    else:
        try:
            logger.debug(f"Serving file: {file_path} as {content_type}")
            
            # Update last access time for cache tracking
            static_name = file_id[:4]
            db.update_last_access(static_name)
            
            with open(file_path, 'rb') as img_file:
                img_data = img_file.read()
            return Response(
                img_data,
                mimetype=content_type,
                headers=response_headers
            )
            
        except Exception as e:
            logger.error(f"Error serving file {file_path}: {e}")
            return 'File serving failed', 500, {'Content-Type': 'text/plain'}

@app.route('/servercmd/<command>/<additional>/<time_param>/<key>')
@app.route('/servercmd/<command>/<time_param>/<key>', defaults={'additional': ''})
def servercmd(command: str, additional: str, time_param: str, key: str):
    # Check hath_config before using it
    hath_config = get_hath_config()
    if not hath_config or not getattr(hath_config, 'client_id', None) or not getattr(hath_config, 'client_key', None):
        logger.error("Missing hath_config, client_id or client_key for remote fetch")
        return 'Internal Server Error', 500, {'Content-Type': 'text/plain'}

    """Handle server commands with authentication."""
    # Log access request
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))

    # reject if not from rpc server
    if client_ip not in hath_config.rpc_server_ips:
        logger.warning(f"Unauthorized command attempt from IP: {client_ip}")
        return "Forbidden", 403, {'Content-Type': 'text/plain'}

    # Verify authentication key
    import verification_manager
    if not verification_manager.verify_servercmd_key(command, additional, time_param, key):
        logger.warning(f"Invalid authentication key for servercmd: {command}")
        return "Forbidden", 403, {'Content-Type': 'text/plain'}

    logger.debug(f"Received servercmd: {command} with additional: {additional}")
    
    # Parse additional parameters
    params = parse_additional_params(additional)
    
    # Handle different commands
    if command == 'still_alive':
        logger.debug("Processing still_alive command")
        return "I feel FANTASTIC and I'm still alive", 200, {'Content-Type': 'text/plain'}
    
    elif command == 'speed_test':
        # Get testsize from additional parameters
        testsize_str = params.get('testsize', '0')
        try:
            testsize = int(testsize_str)
            if testsize < 0 or testsize > 100 * 1024 * 1024:  # Limit to 100MB
                return 'Invalid testsize', 400, {'Content-Type': 'text/plain'}
            
            # Generate actual data for speed test
            logger.info(f"Processing speed_test command with testsize: {testsize}")
            
            # Generate data efficiently in chunks
            def generate_test_data():
                chunk_size = 8192  # 8KB chunks
                remaining = testsize
                chunk_data = b'0' * chunk_size
                
                while remaining > 0:
                    if remaining >= chunk_size:
                        yield chunk_data
                        remaining -= chunk_size
                    else:
                        yield b'0' * remaining
                        remaining = 0
            
            return Response(
                generate_test_data(),
                status=200,
                headers={
                    'Content-Type': 'application/octet-stream',
                    'Content-Length': str(testsize)
                }
            )
            
        except ValueError:
            return 'Invalid testsize format', 400, {'Content-Type': 'text/plain'}
    
    elif command == 'threaded_proxy_test':
        # Get required parameters from additional
        scheme = params.get('protocol', 'http')
        hostname = params.get('hostname', 'localhost')
        port = params.get('port', '80')
        testsize = params.get('testsize', '1024')
        testtime = params.get('testtime', '10')
        testkey = params.get('testkey', 'default')
        testcount_str = params.get('testcount', '1')
        
        try:
            testcount = int(testcount_str)
            if testcount <= 0 or testcount > 100:  # Limit concurrent requests
                return 'Invalid testcount (1-100)', 400, {'Content-Type': 'text/plain'}
                
            logger.info(f"Processing threaded_proxy_test with {testcount} concurrent requests")
            
            # Function to make a single request
            def make_request():
                try:
                    random_val = random.randint(0, 2147483647)
                    url = f"{scheme}://{hostname}:{port}/t/{testsize}/{testtime}/{testkey}/{random_val}"
                    logger.debug(f"Making request to: {url}")
                    start_time = time.time()
                    response = requests.get(url, timeout=30)
                    end_time = time.time()
                    
                    return end_time - start_time, response.status_code == 200
                except Exception as e:
                    logger.error(f"Request failed: {e}")
                    return 0, False
            
            # Execute concurrent requests
            start_total = time.time()
            with ThreadPoolExecutor(max_workers=testcount) as executor:
                futures = [executor.submit(make_request) for _ in range(testcount)]
                results = [future.result() for future in futures]
            end_total = time.time()
            
            total_time = end_total - start_total
            total_time_ms = int(total_time * 1000)  # Convert to milliseconds
            successful_requests = sum(1 for _, success in results if success)
            
            logger.info(f"Threaded proxy test completed: {successful_requests}/{testcount} successful in {total_time:.2f}s ({total_time_ms}ms)")
            
            return f"OK:{successful_requests}-{total_time_ms}", 200, {'Content-Type': 'text/plain'}
            
        except ValueError:
            return 'Invalid testcount format', 400, {'Content-Type': 'text/plain'}
        except Exception as e:
            logger.error(f"Threaded proxy test error: {e}")
            return 'Test execution failed', 500, {'Content-Type': 'text/plain'}

    elif command == 'refresh_cert':
        logger.info("Processing refresh_cert command")
        
        if not hath_config:
            logger.error("Configuration not available for certificate refresh")
            return "FAIL: Configuration not available", 500, {'Content-Type': 'text/plain'}
        
        try:
            # Log current certificate status
            import os
            cert_path = os.path.join(hath_config.data_dir, "client.crt")
            if os.path.exists(cert_path):
                stat = os.stat(cert_path)
                logger.debug(f"Current certificate last modified: {time.ctime(stat.st_mtime)}")
            else:
                logger.warning("No existing certificate found")
            
            # Force download of new certificate
            logger.debug("Downloading new SSL certificate...")
            success = hath_config.get_ssl_certificate(force_refresh=True)
            if success:
                logger.info("Certificate refreshed successfully")
                
                # Verify new certificate was created
                if os.path.exists(cert_path):
                    new_stat = os.stat(cert_path)
                    logger.debug(f"New certificate created: {time.ctime(new_stat.st_mtime)}")
                
                # Update Flask config with new certificate paths
                hath_config.cert_file = os.path.join(hath_config.data_dir, "client.crt")
                hath_config.key_file = os.path.join(hath_config.data_dir, "client.key")
                
                # Schedule server restart in a separate thread
                def restart_server():
                    logger.debug("Scheduling server restart to apply new certificate...")
                    time.sleep(2)  # Give time for response to be sent
                    logger.debug("Restarting server with new certificate...")
                    os._exit(0)  # Force exit to trigger restart (if running under supervisor/systemd)
                
                import threading
                threading.Thread(target=restart_server, daemon=True).start()
                
                return "Certificate refreshed successfully. Server will restart in 2 seconds to apply new certificate.", 200, {'Content-Type': 'text/plain'}
            else:
                logger.error("Failed to refresh certificate")
                return "FAIL: Certificate refresh failed", 500, {'Content-Type': 'text/plain'}
                
        except Exception as e:
            logger.error(f"Certificate refresh error: {e}")
            return f"FAIL: Certificate refresh failed - {str(e)}", 500, {'Content-Type': 'text/plain'}
        
    elif command == 'refresh_settings':
        logger.info("Processing refresh_settings command")
        
        if not hath_config:
            logger.error("Configuration not available for settings refresh")
            return "FAIL: Configuration not available", 500, {'Content-Type': 'text/plain'}
        
        try:
            # Force download of new settings
            logger.info("Downloading new settings...")
            success = hath_config.get_client_config(force_refresh=True)
            if success:
                import event_manager
                event_manager.update_logging_level()
                return "Settings refreshed successfully", 200, {'Content-Type': 'text/plain'}
            else:
                logger.error("Failed to refresh settings")
                return "FAIL: Settings refresh failed", 500, {'Content-Type': 'text/plain'}
                
        except Exception as e:
            logger.error(f"Settings refresh error: {e}")
            return f"FAIL: Settings refresh failed - {str(e)}", 500, {'Content-Type': 'text/plain'}
    
    else:
        logger.warning(f"Unknown servercmd command: {command}")
        return 'Unknown command', 400, {'Content-Type': 'text/plain'}


@app.route('/t/<testsize>/<testtime>/<key>')
@app.route('/t/<testsize>/<testtime>/<key>/<random>')
def speed_test_endpoint(testsize: str, testtime: str, key: str, random: str = ""):
    """Speed test endpoint with optional random parameter."""
    # Log access request
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))
    
    # Verify authentication key
    import verification_manager
    if not verification_manager.verify_speed_test_key(testsize, testtime, key):
        logger.warning(f"Invalid authentication key for /t/ endpoint: testsize={testsize}, testtime={testtime}")
        return "Forbidden", 403, {'Content-Type': 'text/plain'}
    
    try:
        testsize_int = int(testsize)
        if testsize_int < 0 or testsize_int > 100 * 1024 * 1024:  # Limit to 100MB
            logger.warning(f"Invalid testsize for /t/ endpoint: {testsize}")
            return "Invalid testsize", 400, {'Content-Type': 'text/plain'}
                
        # Generate actual data for speed test
        def generate_test_data():
            chunk_size = 8192  # 8KB chunks
            remaining = testsize_int
            chunk_data = b'0' * chunk_size
            
            while remaining > 0:
                if remaining >= chunk_size:
                    yield chunk_data
                    remaining -= chunk_size
                else:
                    yield b'0' * remaining
                    remaining = 0
        
        return Response(
            generate_test_data(),
            status=200,
            headers={
                'Content-Type': 'application/octet-stream',
                'Content-Length': str(testsize_int)
            }
        )
        
    except ValueError:
        return 'Invalid testsize format', 400, {'Content-Type': 'text/plain'}
    except Exception as e:
        logger.error(f"Speed test endpoint error: {e}")
        return 'Test execution failed', 500, {'Content-Type': 'text/plain'}


@app.route('/favicon.ico')
def favicon():
    """Redirect to E-Hentai favicon."""
    return redirect('https://e-hentai.org/favicon.ico', code=301)


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return "File not found", 404, {'Content-Type': 'text/plain'}


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return "Internal Server Error", 500, {'Content-Type': 'text/plain'}

def create_app():
    """Create and configure the Flask application."""
    
    logger.info(f"Process {os.getpid()}: Starting Hentai@Home Flask worker...")
    
    # Get configuration - will try to load from cache if not already initialized
    hath_config = get_hath_config()
    if hath_config is None:
        logger.info("Configuration not found in cache, initializing fresh configuration...")
        
        # Initialize configuration from scratch (development mode or cache failure)
        hath_config = HathConfig()
        
        if not hath_config.initialize():
            logger.error("Failed to initialize configuration")
            raise RuntimeError("Configuration initialization failed")
        
        # Initialize the singleton with our config
        initialize_config(hath_config)

        # Initialize database
        db.initialize_database()

        # Update logging level based on configuration
        import event_manager
        event_manager.update_logging_level()

        # Validate cache before notifying the server
        import cache_manager
        cache_manager.cache_validation()
        
        # Start notification in background - it will wait for server to be ready
        import notification_manager
        # do not notify master
        # notification_manager.notify_server_startup()

        # Start configuration file monitoring
        event_manager.start_config_file_monitor()

        # Setup shutdown handlers for graceful shutdown
        notification_manager.setup_shutdown_handlers()
    else:
        logger.info(f"Process {os.getpid()}: Using cached configuration from main process")

    logger.info(f'Process {os.getpid()}: successfully loaded configuration')

    return app


if __name__ == '__main__':
    try:
        # Create and configure the app
        app = create_app()
        
        # Get Flask configuration from hath_config
        hath_config = get_hath_config()
        if not hath_config:
            logger.error("Configuration not available")
            raise RuntimeError("Configuration not available")
            
        flask_config = hath_config.get_flask_config()
        
        logger.debug(f"Starting Flask development server on {flask_config['host']}:{flask_config['port']}")
        
        if flask_config['ssl_context']:
            logger.debug("SSL enabled with client certificate")
        
        # Start the Flask application (this is blocking)
        app.run(
            host=flask_config['host'],
            port=flask_config['port'],
            ssl_context=flask_config['ssl_context'],
            debug=flask_config['debug'],
            threaded=flask_config['threaded']
        )
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise
