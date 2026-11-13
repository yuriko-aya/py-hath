"""Server command dispatch and the /t/ speed-test endpoint."""

from __future__ import annotations

import logging
import os
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from flask import Response, request

from hath import cache
from hath.certs import get_ssl_certificate
from hath.config import apply_hot_reload_settings, get_client_config, get_client_ip, get_config
from hath.download import trigger_download
from hath.http.app import app
from hath.http.params import parse_additional_params
from hath.http_client import get
from hath.lifecycle import restart_gunicorn
from hath.verification import verify_servercmd_key, verify_speed_test_key

logger = logging.getLogger(__name__)


def generate_speed_test_data(testsize_int):
    sleep_time = cache.get_throttled_speed()
    chunk_size = 8192
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
    hath_config = get_config()

    if not hath_config.client_id or not hath_config.client_key:
        logger.error("Missing hath_config, client_id or client_key for remote fetch")
        return 'Internal Server Error', 500, {'Content-Type': 'text/plain'}

    client_ip = get_client_ip(request.environ)

    if not hath_config.disable_ip_check and client_ip not in hath_config.rpc_server_ips:
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

    if not verify_servercmd_key(command, additional, time_param, key):
        logger.warning(f"Invalid authentication key for servercmd: {command}")
        return "Forbidden", 403, {'Content-Type': 'text/plain'}

    logger.debug(f"Received servercmd: {command} with additional: {additional}")

    params = parse_additional_params(additional)

    if command == 'still_alive':
        logger.debug("Processing still_alive command")
        return "I feel FANTASTIC and I'm still alive", 200, {'Content-Type': 'text/plain'}

    elif command == 'speed_test':
        testsize_str = params.get('testsize', '0')
        try:
            testsize = int(testsize_str)
            if testsize < 0 or testsize > 100 * 1024 * 1024:
                return 'Invalid testsize', 400, {'Content-Type': 'text/plain'}

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
        scheme = params.get('protocol', 'http')
        hostname = params.get('hostname', 'localhost')
        port = params.get('port', '80')
        testsize = params.get('testsize', '1024')
        testtime = params.get('testtime', '10')
        testkey = params.get('testkey', 'default')
        testcount_str = params.get('testcount', '1')

        try:
            testcount = int(testcount_str)
            if testcount <= 0 or testcount > 100:
                return 'Invalid testcount (1-100)', 400, {'Content-Type': 'text/plain'}

            logger.info(f"Processing threaded_proxy_test with {testcount} concurrent requests")

            def make_request():
                try:
                    random_val = random.randint(0, 2147483647)
                    url = f"{scheme}://{hostname}:{port}/t/{testsize}/{testtime}/{testkey}/{random_val}"
                    logger.debug(f"Making request to: {url}")
                    start_time = time.time()
                    response = get(url, timeout=30)
                    end_time = time.time()

                    return end_time - start_time, response.status_code == 200
                except Exception as e:
                    logger.error(f"Request failed: {e}")
                    return 0, False

            start_total = time.time()
            with ThreadPoolExecutor(max_workers=testcount) as executor:
                futures = [executor.submit(make_request) for _ in range(testcount)]
                results = [future.result() for future in futures]
            end_total = time.time()

            total_time = end_total - start_total
            total_time_ms = int(total_time * 1000)
            successful_requests = sum(1 for _, success in results if success)

            logger.info(
                f"Threaded proxy test completed: {successful_requests}/{testcount} "
                f"successful in {total_time:.2f}s ({total_time_ms}ms)"
            )

            return f"OK:{successful_requests}-{total_time_ms}", 200, {'Content-Type': 'text/plain'}

        except ValueError:
            return 'Invalid testcount format', 400, {'Content-Type': 'text/plain'}
        except Exception as e:
            logger.error(f"Threaded proxy test error: {e}")
            return 'Test execution failed', 500, {'Content-Type': 'text/plain'}

    elif command == 'refresh_cert' or command == 'refresh_certs':
        logger.info("Processing refresh_cert command")

        try:
            cert_path = os.path.join(hath_config.data_dir, "client.crt")
            if os.path.exists(cert_path):
                stat = os.stat(cert_path)
                logger.debug(f"Current certificate last modified: {time.ctime(stat.st_mtime)}")
            else:
                logger.warning("No existing certificate found")

            logger.debug("Downloading new SSL certificate...")
            success = get_ssl_certificate(force_refresh=True)
            if success:
                logger.info("Certificate refreshed successfully")

                if os.path.exists(cert_path):
                    new_stat = os.stat(cert_path)
                    logger.debug(f"New certificate created: {time.ctime(new_stat.st_mtime)}")

                hath_config.cert_file = os.path.join(hath_config.data_dir, "client.crt")
                hath_config.key_file = os.path.join(hath_config.data_dir, "client.key")

                def restart_server():
                    logger.debug("Scheduling server restart to apply new certificate...")
                    time.sleep(2)
                    logger.debug("Restarting server with new certificate...")
                    restart_gunicorn()

                threading.Thread(target=restart_server, daemon=True).start()

                return (
                    "Certificate refreshed successfully. Server will restart in 2 seconds to apply new certificate.",
                    200,
                    {'Content-Type': 'text/plain'},
                )
            logger.error("Failed to refresh certificate")
            return "FAIL: Certificate refresh failed", 500, {'Content-Type': 'text/plain'}

        except Exception as e:
            logger.error(f"Certificate refresh error: {e}")
            return f"FAIL: Certificate refresh failed - {str(e)}", 500, {'Content-Type': 'text/plain'}

    elif command == 'refresh_settings':
        logger.info("Processing refresh_settings command")

        try:
            logger.info("Downloading new settings...")
            success = get_client_config(force_refresh=True)
            if success:
                apply_hot_reload_settings()
                logger.info("Settings refreshed successfully")
                return "Settings refreshed successfully (log level applied if overridden)", 200, {'Content-Type': 'text/plain'}
            logger.error("Failed to refresh settings")
            return "FAIL: Settings refresh failed", 500, {'Content-Type': 'text/plain'}

        except Exception as e:
            logger.error(f"Settings refresh error: {e}")
            return f"FAIL: Settings refresh failed - {str(e)}", 500, {'Content-Type': 'text/plain'}

    elif command == 'start_downloader':
        logger.info("Processing start_downloader command")

        trigger_download()
        return '', 200, {'Content-Type': 'text/plain'}
    else:
        logger.warning(f"Unknown servercmd command: {command}")
        return 'Unknown command', 400, {'Content-Type': 'text/plain'}


@app.route('/t/<testsize>/<testtime>/<key>')
@app.route('/t/<testsize>/<testtime>/<key>/<random>')
def speed_test_endpoint(testsize: str, testtime: str, key: str, random: str = ""):
    """Speed test endpoint with optional random parameter."""
    if not verify_speed_test_key(testsize, testtime, key):
        logger.warning(f"Invalid authentication key for /t/ endpoint: testsize={testsize}, testtime={testtime}")
        return "Forbidden", 403, {'Content-Type': 'text/plain'}

    try:
        testsize_int = int(testsize)
        if testsize_int < 0 or testsize_int > 100 * 1024 * 1024:
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
