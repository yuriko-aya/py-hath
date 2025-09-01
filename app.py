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

def update_logging_level():
    """Update logging level based on hath_config settings."""
    global hath_config
    
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
    global hath_config
    
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

# Setup file logging
setup_file_logging()

logger = logging.getLogger(__name__)

app = Flask(__name__)

# Global configuration instance
hath_config = None

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


def verify_servercmd_key(command: str, additional: str, time_param: str, provided_key: str) -> bool:
    """Verify the authentication key for servercmd endpoint."""
    if not hath_config or not hath_config.client_id or not hath_config.client_key:
        return False
    
    # Generate expected key: SHA-1 of "hentai@home-servercmd-{command}-{additional}-{client_id}-{time}-{client_key}"
    data = f"hentai@home-servercmd-{command}-{additional}-{hath_config.client_id}-{time_param}-{hath_config.client_key}"
    expected_key = hashlib.sha1(data.encode()).hexdigest()
    
    return provided_key == expected_key


def verify_speed_test_key(testsize: str, testtime: str, provided_key: str) -> bool:
    """Verify the authentication key for /t/ speed test endpoint."""
    if not hath_config or not hath_config.client_id or not hath_config.client_key:
        return False
    
    # Generate expected key: SHA-1 of "hentai@home-speedtest-{testsize}-{testtime}-{client_id}-{client_key}"
    data = f"hentai@home-speedtest-{testsize}-{testtime}-{hath_config.client_id}-{hath_config.client_key}"
    expected_key = hashlib.sha1(data.encode()).hexdigest()
    
    return provided_key == expected_key


def verify_h_endpoint_auth(keystamp: str, expected: str, file_id: str) -> bool:
    """Verify authentication for /h/ endpoint."""
    if not hath_config or not hath_config.client_key:
        return False
    
    try:
        # Check if keystamp is within 900 seconds (15 minutes)
        current_time = int(time.time())
        keystamp_int = int(keystamp)
        time_diff = abs(current_time - keystamp_int)
        
        if time_diff > 900:
            logger.warning(f"Keystamp too old: {time_diff} seconds difference")
            return False
        
        # Generate expected hash: first 10 chars of "{keystamp}-{fileid}-{client_key}-hotlinkthis"
        hash_data = f"{keystamp}-{file_id}-{hath_config.client_key}-hotlinkthis"
        full_hash = hashlib.sha1(hash_data.encode()).hexdigest()
        expected_hash = full_hash[:10]
        
        return expected == expected_hash
        
    except ValueError:
        logger.warning(f"Invalid keystamp format: {keystamp}")
        return False

def fetch_remote_file(fileindex: str, xres: str, file_id: str,):
    try:
        # Check hath_config before using it
        if not hath_config or not getattr(hath_config, 'client_id', None) or not getattr(hath_config, 'client_key', None):
            logger.error("Missing hath_config, client_id or client_key for remote fetch")
            return False, None
        # Prepare actkey and acttime
        current_acttime = hath_config.get_current_acttime()
        add = f"{fileindex};{xres};{file_id}"
        # actkey is SHA-1 of "hentai@home-srfetch-{add}-{client_id}-{current_acttime}-{client_key}"
        if not hath_config or not hath_config.client_id or not hath_config.client_key:
            logger.error("Missing client_id or client_key for remote fetch")
            return False, None
        actkey_data = f"hentai@home-srfetch-{add}-{hath_config.client_id}-{current_acttime}-{hath_config.client_key}"
        actkey = hashlib.sha1(actkey_data.encode()).hexdigest()
        url_path = (
            f"/15/rpc?clientbuild=176&act=srfetch"
            f"&add={add}&cid={hath_config.client_id}&acttime={current_acttime}&actkey={actkey}"
        )
        logger.debug(f"Fetching file location via RPC: {url_path}")
        resp = hath_config._make_rpc_request(url_path, timeout=20)
        # Find the first line starting with http
        urls = []
        for line in resp.text.splitlines():
            if line.startswith('http'):
                urls.append(line.strip())
        if not urls:
            logger.error("No valid URL found in srfetch response")
            return False, None
        logger.debug(f"Found {len(urls)} URLs in srfetch response: {urls}")
        for url in urls:
            for attempt in range(1, 4):  # up to 3 retries per URL
                try:
                    logger.debug(f"Attempt {attempt} - Downloading file from: {url}")
                    file_resp = requests.get(url, timeout=10, stream=True)
                    file_resp.raise_for_status()
                    logger.debug(f"Successfully downloaded from {url}")
                    return True, file_resp  # ✅ stop immediately after success
                except Exception as e:
                    logger.error(f"Attempt {attempt} - Failed to download {url}: {e}")
            logger.error(f"Max retries reached for {url}")
        logger.error(f"All URLs {urls} failed to download")
        return False, None

    except Exception as e:
        logger.error(f"Remote fetch or download failed: {e}")
        return False, None

def verify_file_integrity(file_path:str, file_id:str):
    """Verify the integrity of the cached file by comparing its SHA-1 hash with the file_id."""
    # Extract expected hash from file_id (handle different formats)
    if '-' in file_id:
        expected_hash = file_id.split('-')[0]
    else:
        # If no dash, assume the whole file_id is the hash
        expected_hash = file_id
    
    try:
        sha1 = hashlib.sha1()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha1.update(chunk)
        file_hash = sha1.hexdigest()
        if not file_hash == expected_hash:
            logger.debug(f"File integrity check failed for {file_path}: expected {expected_hash}, got {file_hash}")
            return False
        else:
            logger.debug(f"File integrity check passed for {file_path}")
            return True
    except Exception as e:
        logger.error(f"Error verifying file integrity: {e}")
        return False

@app.route('/h/<file_id>/<additional>/<filename>')
def serve_file(file_id: str, additional: str, filename: str):
    """Serve cached files with authentication."""
    # Log access request
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))
    
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
    if not verify_h_endpoint_auth(keystamp_time, expected, file_id):
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
    
    subdirectory = file_id[:2]
    file_path = os.path.join('cache', subdirectory, file_id)

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
        success, file_resp = fetch_remote_file(fileindex, xres, file_id)
        if success:           
            # Save to cache and stream to client simultaneously
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
           
            logger.debug(f"Streaming file: {file_id} as {content_type}")
            return Response(
                generate_and_cache(file_resp),
                mimetype=content_type,
                headers=response_headers
            )
        else:
            return "File not found", 404, {'Content-Type': 'text/plain'}
    
    if not verify_file_integrity(file_path, file_id):
        os.remove(file_path)
        # Prepare remote fetch URL
        success, file_resp = fetch_remote_file(fileindex, xres, file_id)
        if success:
            # Save to cache and stream to client simultaneously
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            logger.debug(f"Streaming file: {file_id} as {content_type}")
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

def blacklist_process(timespan: int):
    logger.debug(f"Processing blacklist for timespan: {timespan}")
    # Check hath_config before using it
    if not hath_config or not getattr(hath_config, 'client_id', None) or not getattr(hath_config, 'client_key', None):
        logger.error("Missing hath_config, client_id or client_key for remote fetch")
        return False, None
    # Prepare actkey and acttime
    current_acttime = hath_config.get_current_acttime()
    add = str(timespan)
    # actkey is SHA-1 of "hentai@home-srfetch-{add}-{client_id}-{current_acttime}-{client_key}"
    if not hath_config or not hath_config.client_id or not hath_config.client_key:
        logger.error("Missing client_id or client_key for remote fetch")
        return False, None
    actkey_data = f"hentai@home-get_blacklist-{add}-{hath_config.client_id}-{current_acttime}-{hath_config.client_key}"
    actkey = hashlib.sha1(actkey_data.encode()).hexdigest()
    url_path = (
        f"/15/rpc?clientbuild=176&act=get_blacklist"
        f"&add={add}&cid={hath_config.client_id}&acttime={current_acttime}&actkey={actkey}"
    )
    resp = hath_config._make_rpc_request(url_path, timeout=20)
    delete_count = 0
    if 'OK' in resp.text:
        logger.debug(f'Receive response {resp.text}')
        for line in resp.text.splitlines():
            if '-' in line:
                subdir = line[2]
                if os.path.exists(os.path.join('cache', subdir, line)):
                    os.remove(os.path.join('cache', subdir, line))
                    delete_count += 1

    return delete_count

@app.route('/servercmd/<command>/<additional>/<time_param>/<key>')
@app.route('/servercmd/<command>/<time_param>/<key>', defaults={'additional': ''})
def servercmd(command: str, additional: str, time_param: str, key: str):
    # Check hath_config before using it
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
    if not verify_servercmd_key(command, additional, time_param, key):
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
                update_logging_level()
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
    if not verify_speed_test_key(testsize, testtime, key):
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


def cache_validation():
    """Validate the cache state before notifying the server."""
    logger.info("Starting cache validation...")
    if not hath_config or not hath_config.client_id or not hath_config.client_key:
        logger.error("Configuration not available for cache validation")
        return False

    try:
        cache_dir = 'cache'
        static_range = hath_config.static_range
        if not static_range or len(static_range) == 0:
            logger.debug("No static range defined, skipping cache validation")
            return True  # Nothing to validate
        files = [p for p in Path(cache_dir).glob("*/*") if p.is_file()]
        file_count = len(files)
        if not files or len(files) == 0:
            logger.debug("Cache is empty. Skipping validation")
            return True

        # Get unique first 4 characters from all files
        unique_prefixes = set()
        for file in files:
            static_name = file.name[:4]
            unique_prefixes.add(static_name)

        # Check if there are any prefixes not in static range
        prefixes_not_in_range = unique_prefixes - set(static_range)
        if not prefixes_not_in_range:
            logger.debug("All file prefixes are in static range")
            return True

        logger.debug(f"Found {len(prefixes_not_in_range)} prefixes not in static range")
        logger.debug("Proceeding with cleanup...")

        ten_percent = max(1, file_count // 10)  # Avoid division by zero
        verified_count = 0
        verified_percent = 0
        deleted_count = 0
        for file in files:
            static_name = file.name[:4]
            if verified_count % ten_percent == 0:
                logger.debug(f"Cache cleanup... ({verified_percent:.1f}%)")

            if static_name not in static_range:
                # Delete files with prefixes not in static range
                os.remove(file)
                deleted_count += 1
            
            verified_count += 1
            verified_percent = (verified_count / file_count) * 100
        logger.info("Cache validation completed successfully")
        if deleted_count > 0:
            logger.warning(f"Deleted {deleted_count} files outside of static range")
        return True
        
    except OSError as e:
        logger.error(f"Error accessing cache directory: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during cache validation: {e}")
        return False

def notify_server_startup():
    """Notify the server that the client has started - runs in background thread."""
    def wait_for_server_and_notify():
        # Wait for Flask server to be ready by checking if port is listening
        max_attempts = 30  # 30 seconds max wait
        attempts = 0
        
        if not hath_config:
            logger.error("hath_config not available for notification")
            return
            
        host = hath_config.config.get('host', '0.0.0.0')
        port = int(hath_config.config.get('port', 5000))
        
        # Convert 0.0.0.0 to localhost for local checking
        check_host = 'localhost' if host == '0.0.0.0' else host
        
        logger.debug(f"Waiting for server to start on {host}:{port}...")
        
        while attempts < max_attempts:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((check_host, port))
                sock.close()
                
                if result == 0:
                    logger.debug("Server is ready, sending startup notification...")
                    success = hath_config.notify_client_start()                    
                    if success:
                        hath_config.is_server_ready = True
                        deleted_blacklist = blacklist_process(259200)
                        logger.debug(f"Processed get_blacklist command, deleted {deleted_blacklist} files") 

                        logger.debug("Startup notification successful, starting periodic still_alive notifications...")
                        # Start periodic still_alive notifications
                        start_periodic_still_alive()
                    else:
                        logger.warning("Startup notification failed, not starting periodic notifications")
                    return
                    
            except Exception:
                pass
            
            attempts += 1
            time.sleep(1)
        
        logger.error("Server did not start within 30 seconds, skipping notification")
    
    # Run notification in background thread
    thread = threading.Thread(target=wait_for_server_and_notify, daemon=True)
    thread.start()


def start_periodic_still_alive():
    """Start periodic still_alive notifications every 5 minutes."""
    def periodic_still_alive():
        counter = 1
        while True:
            try:
                time.sleep(120)  # Wait 2 minutes (120 seconds)

                if not hath_config or not hath_config.client_id or not hath_config.client_key:
                    logger.error("Configuration not available for still_alive notification")
                    continue
                
                # Generate still_alive notification URL
                current_acttime = hath_config.get_current_acttime()
                actkey_data = f"hentai@home-still_alive--{hath_config.client_id}-{current_acttime}-{hath_config.client_key}"
                actkey = hashlib.sha1(actkey_data.encode()).hexdigest()
                
                url_path = (
                    f"/15/rpc?clientbuild=176&act=still_alive"
                    f"&add=&cid={hath_config.client_id}&acttime={current_acttime}&actkey={actkey}"
                )
                
                logger.info("Sending periodic still_alive notification...")
                response = hath_config._make_rpc_request(url_path, timeout=10)
                
                logger.debug(f"Still_alive notification sent successfully: {response.text.strip()}")

                # Every 540 iterations (approximately every 18 hours), run blacklist cleanup
                if counter % 540 == 0:
                    deleted_blacklist = blacklist_process(43200)
                    logger.debug(f"Processed get_blacklist command, deleted {deleted_blacklist} files")
                counter += 1

            except Exception as e:
                logger.error(f"Failed to send still_alive notification: {e}")
                counter += 1
                # Continue running despite errors
    
    # Start periodic notifications in background thread
    thread = threading.Thread(target=periodic_still_alive, daemon=True)
    thread.start()
    logger.debug("Periodic still_alive notifications started (every 2 minutes)")


# Global flag to prevent duplicate shutdown notifications
_shutdown_notification_sent = False
_shutdown_lock = threading.Lock()


def notify_client_stop():
    """Notify the server that the client is stopping."""
    global _shutdown_notification_sent
    
    # Only send notification from the process that holds the background tasks lock
    lock_file = os.path.join('data', '.hath-background-tasks.lock')
    should_notify = False
    
    try:
        if os.path.exists(lock_file):
            with open(lock_file, 'r') as f:
                lock_pid = int(f.read().strip())
            if lock_pid == os.getpid():
                should_notify = True
        else:
            # If no lock file exists, we might be running in single-process mode
            should_notify = True
    except (ValueError, FileNotFoundError):
        # If we can't read the lock file, don't send notification
        should_notify = False
    
    if not should_notify:
        logger.debug(f"Process {os.getpid()}: Skipping client_stop notification (not primary process)")
        return
    
    with _shutdown_lock:
        if _shutdown_notification_sent:
            logger.debug("Client_stop notification already sent, skipping")
            return
        
        _shutdown_notification_sent = True
    
    try:
        if not hath_config or not hath_config.client_id or not hath_config.client_key:
            logger.error("Configuration not available for client_stop notification")
            return
        
        if not hath_config.is_server_ready:
            logger.warning("Server was never marked as ready, skipping client_stop notification")
            return

        logger.info("Sending client_stop notification...")
        
        # Generate client_stop notification URL
        current_acttime = hath_config.get_current_acttime()
        actkey_data = f"hentai@home-client_stop--{hath_config.client_id}-{current_acttime}-{hath_config.client_key}"
        actkey = hashlib.sha1(actkey_data.encode()).hexdigest()
        
        url_path = (
            f"/15/rpc?clientbuild=176&act=client_stop"
            f"&add=&cid={hath_config.client_id}&acttime={current_acttime}&actkey={actkey}"
        )
        
        response = hath_config._make_rpc_request(url_path, timeout=10)
        
        logger.debug(f"Client_stop notification sent successfully: {response.text.strip()}")
        
        # Clean up config cache when shutting down
        hath_config.cleanup_config_cache()
        
    except Exception as e:
        logger.error(f"Failed to send client_stop notification: {e}")
        # Still try to clean up config cache even if notification failed
        if hath_config:
            hath_config.cleanup_config_cache()


def setup_shutdown_handlers():
    """Setup signal handlers and atexit for graceful shutdown."""
    
    def signal_handler(signum, frame):
        """Handle shutdown signals."""
        try:
            signal_name = signal.Signals(signum).name if hasattr(signal, 'Signals') else str(signum)
            logger.info(f"Received signal {signal_name}, shutting down gracefully...")
            stop_config_file_monitor()
            notify_client_stop()
        except Exception as e:
            # Avoid logging during shutdown as it might cause issues
            pass
        finally:
            # Exit without calling sys.exit() to avoid conflicts with threading cleanup
            os._exit(0)
    
    def atexit_handler():
        """Handle normal exit."""
        try:
            stop_config_file_monitor()
            notify_client_stop()
        except Exception:
            # Silently handle any exceptions during shutdown
            pass
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Termination signal
    
    # Register atexit handler for normal shutdown
    atexit.register(atexit_handler)
    
    logger.debug("Shutdown handlers registered for graceful client_stop notification")


def create_app():
    """Create and configure the Flask application."""
    global hath_config
    
    logger.info(f"Process {os.getpid()}: Starting Hentai@Home Flask client...")
    
    # Only initialize hath_config and run background tasks on one process using a lock file approach
    # Place lock file in data directory and make it hidden
    lock_file = os.path.join('data', '.hath-background-tasks.lock')
    should_run_background_tasks = False
    
    # Ensure data directory exists
    os.makedirs('data', exist_ok=True)
    
    # Clean up stale lock files first
    if os.path.exists(lock_file):
        try:
            with open(lock_file, 'r') as f:
                existing_pid = int(f.read().strip())
            
            # Check if the process is still running
            try:
                os.kill(existing_pid, 0)  # This doesn't kill, just checks if process exists
                logger.debug(f"Process {os.getpid()}: Configuration and background tasks already handled by process {existing_pid}")
            except (OSError, ProcessLookupError):
                # Process doesn't exist anymore, remove stale lock file
                os.remove(lock_file)
                logger.debug(f"Process {os.getpid()}: Removed stale lock file from non-existent process {existing_pid}")
        except (ValueError, FileNotFoundError):
            # Invalid or corrupted lock file, remove it
            try:
                os.remove(lock_file)
                logger.warning(f"Process {os.getpid()}: Removed corrupted lock file")
            except FileNotFoundError:
                pass
    
    # Try to acquire the lock
    try:
        # Try to create a lock file
        with open(lock_file, 'x') as f:
            f.write(str(os.getpid()))
        should_run_background_tasks = True
        logger.info(f"Process {os.getpid()}: Acquired configuration and background tasks lock at {lock_file}")
    except FileExistsError:
        # Lock file already exists, another process is handling initialization
        try:
            with open(lock_file, 'r') as f:
                existing_pid = int(f.read().strip())
            logger.debug(f"Process {os.getpid()}: Configuration and background tasks handled by process {existing_pid}")
        except (ValueError, FileNotFoundError):
            logger.warning(f"Process {os.getpid()}: Invalid lock file, will not run background tasks")
    
    if should_run_background_tasks:
        logger.debug("Initializing configuration and running background tasks on primary process...")
        
        # Initialize configuration (only on primary process)
        hath_config = HathConfig()
        
        if not hath_config.initialize():
            logger.error("Failed to initialize configuration")
            raise RuntimeError("Configuration initialization failed")

        # Update logging level based on configuration
        update_logging_level()
                
        # Validate cache before notifying the server
        cache_validation()
        
        # Start notification in background - it will wait for server to be ready
        notify_server_startup()
        
        # Setup cleanup of lock file and config cache on exit
        def cleanup_primary_process():
            try:
                # Stop configuration file monitoring
                stop_config_file_monitor()
                
                if os.path.exists(lock_file):
                    os.remove(lock_file)
                    logger.debug(f"Background tasks lock file cleaned up: {lock_file}")
                # Clean up config cache
                if hath_config:
                    hath_config.cleanup_config_cache()
            except Exception as e:
                logger.error(f"Failed to clean up primary process files: {e}")
        
        atexit.register(cleanup_primary_process)
    else:
        logger.debug("Waiting for configuration to be initialized by primary process...")
        
        # Wait for the primary process to complete initialization
        # We'll try to load an existing configuration or wait for it to be ready
        max_wait_time = 60  # Wait up to 60 seconds
        wait_start = time.time()
        
        while time.time() - wait_start < max_wait_time:
            try:
                # Try to create a HathConfig and see if we can load existing data
                if os.path.exists('data/client_login') and os.path.exists('data/client.crt'):
                    hath_config = HathConfig()
                    # Load basic credentials
                    if hath_config.read_client_credentials():
                        # Try to load full configuration from cache file
                        if hath_config.load_config_cache():
                            logger.info(f"Process {os.getpid()}: Loaded full configuration from cache file")
                            # Update logging level based on configuration
                            update_logging_level()
                            break
                        else:
                            # Fallback to basic paths if cache not available
                            hath_config.cert_file = os.path.join(hath_config.data_dir, 'client.crt')
                            hath_config.key_file = os.path.join(hath_config.data_dir, 'client.key')
                            logger.warning(f"Process {os.getpid()}: Using basic configuration (cache not available)")
                            break
                else:
                    time.sleep(1)  # Wait a bit more
            except Exception:
                time.sleep(1)
        else:
            # Timeout - fallback to own initialization
            logger.warning(f"Process {os.getpid()}: Timeout waiting for primary process, initializing own config")
            hath_config = HathConfig()
            if not hath_config.initialize():
                logger.error("Failed to initialize configuration")
                raise RuntimeError("Configuration initialization failed")
            # Update logging level based on configuration
            update_logging_level()
            # Start configuration file monitoring for fallback processes
            start_config_file_monitor()
    
    # Always setup shutdown handlers for graceful shutdown
    setup_shutdown_handlers()

    # Start configuration file monitoring for all processes
    start_config_file_monitor()

    logger.info(f'Process {os.getpid()}: successfully loaded configuration')

    return app


if __name__ == '__main__':
    try:
        # Create and configure the app
        app = create_app()
        
        # Get Flask configuration from hath_config
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
