import logging
import hashlib
import time
import random
import requests
import os
import mimetypes
import shutil
import sys

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, g, jsonify, request, Response, send_file, redirect, url_for
from config_singleton import get_hath_config, initialize_config
from log_manager import setup_file_logging

setup_file_logging()

logger = logging.getLogger(__name__)

requests_headers = {
    'User-Agent': 'Hentai@Home Python Client 0.2'
}

app = Flask(__name__)

@app.before_request
def handle_double_slash_in_servercmd():
    """Handle the double slash case in servercmd URLs."""
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
    if response.status_code == 200 or response.status_code == 301:
        logger.info(f'{request.remote_addr} - OK[{response.status_code}]: {request.method} {request.path}')
    else:
        logger.warning(f'{request.remote_addr} - WARNING[{response.status_code}]: {request.method} {request.path}')
    return response

@app.route('/')
def index():
    """Basic health check endpoint."""
    return 'Hentai@Home Python Client', {'Content-Type': 'text/plain'}

def parse_additional_params(additional: str) -> dict:
    """Parse additional parameters from key=value;key=value format."""
    params = {}
    if additional:
        for pair in additional.split(';'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                params[key.strip()] = value.strip()
    return params

@app.route('/status/<actkey>')
def status(actkey: str):
    """Get the current status of the server."""
    # Check hath_config before using it
    hath_config = get_hath_config()
    if not hath_config or not getattr(hath_config, 'client_id', None) or not getattr(hath_config, 'client_key', None):
        logger.error("Missing hath_config, client_id or client_key for remote fetch")
        return 'Internal Server Error', 500, {'Content-Type': 'text/plain'}

    expected = hashlib.sha1(f'hentai@home-status-{hath_config.client_id}'.encode()).hexdigest()
    if not actkey or actkey != expected:
        return "Forbidden", 403, {'Content-Type': 'text/plain'}

    import db_manager
    try:
        cache_status = db_manager.get_cache_stats()
        return jsonify({"status": "ok", "cache": cache_status})
    except Exception as e:
        logger.error(f"Error fetching cache status: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/h/<file_id>/<additional>/<filename>')
def serve_file(file_id: str, additional: str, filename: str):
    import cache_manager
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
    if 'wbp' in filename or '-wbp' in file_id:
        content_type = 'image/webp'
    else:
        content_type, _ = mimetypes.guess_type(filename)
        if not content_type:
            content_type = 'application/octet-stream'

    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        logger.debug(f"File not found locally: {file_path}, attempting remote fetch...")
        if os.path.exists(file_path) and os.path.isdir(file_path):
            shutil.rmtree(file_path)
        # Prepare remote fetch URL
        success, file_resp = cache_manager.fetch_remote_file(fileindex, xres, file_id)
        if success and file_resp:
            # Save to cache and stream to client simultaneously
            file_size = len(file_resp.content)
            logger.debug(f"Streaming file: {file_id} as {content_type}")
            return Response(
                cache_manager.generate_and_cache(file_path, file_id, file_resp, file_size),
                mimetype=content_type,
                headers=response_headers
            )
        else:
            return "File not found", 404, {'Content-Type': 'text/plain'}

    if not cache_manager.verify_file_integrity(file_path, file_id):
        os.remove(file_path)
        # Prepare remote fetch URL
        success, file_resp = cache_manager.fetch_remote_file(fileindex, xres, file_id)
        if success and file_resp:
            # Save to cache and stream to client simultaneously
            file_size = len(file_resp.content)
            file_size_kb = file_size / 1024
            logger.info(f"Streaming {file_size_kb:.2f} kB file: {file_id} as {content_type}")

            return Response(
                cache_manager.generate_and_cache(file_path, file_id, file_resp, file_size),
                mimetype=content_type,
                headers=response_headers
            )
        else:
            return "File not found", 404, {'Content-Type': 'text/plain'}

    else:
        try:
            # Update last access time for cache tracking
            file_size = Path(file_path).stat().st_size
            file_size_kb = file_size / 1024
            logger.info(f"Serving {file_size_kb:.2f} kB file: {file_path} as {content_type}")

            return Response(
                cache_manager.serve_from_file(file_path, file_id),
                mimetype=content_type,
                headers=response_headers
            )
            
        except Exception as e:
            logger.error(f"Error serving file {file_path}: {e}")
            return 'File serving failed', 500, {'Content-Type': 'text/plain'}

def generate_speed_test_data(testsize_int):
    import cache_manager
    sleep_time = cache_manager.get_throttled_speed()
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
        time.sleep(sleep_time)

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

    current_time = time.time()
    try:
        if int(time_param) < current_time - 300:
            logger.warning(f'Received expired servercmd: {command}, {additional}, {time_param}, {key}')
            return 'Get servercmd with expired key', 403, {'Content-Type': 'text/plain'}
    except Exception as e:
        logger.warning(f'Invalid time parameter in servercmd: {time_param}, error: {e}')
        return 'Invalid time parameter', 400, {'Content-Type': 'text/plain'}

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
            logger.debug(f"Processing speed_test command with testsize: {testsize}")
            
            return Response(
                generate_speed_test_data(testsize),
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
                    response = requests.get(url, headers=requests_headers, timeout=30)
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
        current_time = time.time()
        try:
            if current_time - int(testtime) > 300:
                logger.warning(f'Received expired speed test: {testsize}, {testtime}, {key}')
                return 'Get speed test with expired key', 403, {'Content-Type': 'text/plain'}
        except Exception as e:
            logger.error(f"Error processing speed test: {e}")
            return 'Error processing speed test', 400, {'Content-Type': 'text/plain'}
        logger.debug(f'Serving speed test of {testsize_int} bytes')
        return Response(
            generate_speed_test_data(testsize_int),
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
        logger.error("No configuration found, bail out...")
        sys.exit()
    else:
        logger.info(f"Process {os.getpid()}: Using cached configuration from main process")

    logger.info(f'Process {os.getpid()}: successfully loaded configuration')

    return app

