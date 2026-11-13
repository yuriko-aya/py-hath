import atexit
import logging
import os
import signal
import socket
import sys
import threading
import time

from hath import cache, db, storage
from hath.config import get_config, remove_config
from hath.rpc import call_rpc

logger = logging.getLogger(__name__)


def resolve_listen_port(hath_config) -> int:
    """Port Gunicorn binds: CLI/settings override, otherwise the server-assigned port."""
    if hath_config.override_port:
        return int(hath_config.hath_port)
    return int(hath_config.server.get('port', 5000))


def notify_client_start() -> bool:
    """Notify the server that the client has started."""
    try:
        result = call_rpc("client_start", timeout=60)

        logger.debug("Server notification sent successfully")
        logger.debug("Server response: %s", result.body_text or result.fail_code)
        return result.ok

    except Exception as e:
        logger.error(f"Error notifying server of client start: {e}")
        return False


def start_background_task():
    """Notify the server that the client has started - runs in background thread."""
    hath_config = get_config()

    def wait_for_server_and_notify():
        # Wait for Flask server to be ready by checking if port is listening
        max_attempts = 30  # 30 seconds max wait
        attempts = 0

        if not hath_config:
            logger.error("hath_config not available for notification")
            return

        host = hath_config.server.get('host', '0.0.0.0')
        port = resolve_listen_port(hath_config)

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
                    success = notify_client_start()
                    if success:
                        get_config().is_server_ready = True
                        deleted_blacklist = cache.blacklist_process(259200)
                        logger.debug(f"Processed get_blacklist command, deleted {deleted_blacklist} files")

                        logger.debug("Startup notification successful, starting periodic task and notifications...")
                        # Start periodic task and still_alive notifications
                        start_periodic_task()
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


def start_periodic_task():
    """Start periodic task and still_alive notifications."""
    hath_config = get_config()

    def periodic_still_alive():
        counter = 1
        while True:
            try:
                # 2 minutes of each iterations
                time.sleep(120)
                if not hath_config.client_id or not hath_config.client_key:
                    logger.error("Configuration not available for still_alive notification")
                    continue

                logger.info("Sending periodic still_alive notification...")
                result = call_rpc("still_alive", timeout=10)
                logger.debug(
                    "Still_alive notification sent successfully: %s",
                    result.body_text or result.fail_code,
                )

                # Every 540 iterations (approximately every 18 hours), run blacklist cleanup
                if counter % 540 == 0:
                    deleted_blacklist = cache.blacklist_process(43200)
                    logger.debug(f"Processed get_blacklist command, deleted {deleted_blacklist} files")
                counter += 1

                # Every 5 iteration (10 minutes), check if disk and cache size
                if counter % 5 == 0:
                    if not storage.is_disk_ok():
                        sys.exit(0)

                    cache.check_cache_size()

            except Exception as e:
                logger.error(f"Failed to send still_alive notification: {e}")
                counter += 1
                # Continue running despite errors

    # Start periodic notifications in background thread
    thread = threading.Thread(target=periodic_still_alive, daemon=True)
    thread.start()
    logger.debug("Periodic still_alive notifications started (every 2 minutes)")


def notify_client_stop():
    """Notify the server that the client is stopping."""
    hath_config = get_config()

    try:
        if not hath_config.client_id or not hath_config.client_key:
            logger.error("Configuration not available for client_stop notification")
            return

        logger.info("Sending client_stop notification...")

        if get_config().is_server_ready:
            result = call_rpc("client_stop", timeout=10)
            logger.debug(
                "Client_stop notification sent successfully: %s",
                result.body_text or result.fail_code,
            )
        else:
            logger.debug('Server is never ready. Skipping stop notification.')

        # Clean up config cache when shutting down
        remove_config()

        try:
            from hath.metrics import flush_metrics

            flush_metrics()
        except Exception:
            pass

        # Clean up database connections
        db.cleanup_connections()

    except Exception as e:
        logger.error(f"Failed to send client_stop notification: {e}")
        try:
            from hath.metrics import flush_metrics

            flush_metrics()
        except Exception:
            pass
        remove_config()
        db.cleanup_connections()


def setup_shutdown_handlers():
    """Setup signal handlers and atexit for graceful shutdown."""

    def signal_handler(signum, frame):
        """Handle shutdown signals."""
        try:
            signal_name = signal.Signals(signum).name if hasattr(signal, 'Signals') else str(signum)
            logger.info(f"Received signal {signal_name}, shutting down gracefully...")
            notify_client_stop()
        except Exception:
            # Avoid logging during shutdown as it might cause issues
            pass
        finally:
            # Exit without calling sys.exit() to avoid conflicts with threading cleanup
            os._exit(0)

    def atexit_handler():
        """Handle normal exit."""
        try:
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


def restart_gunicorn():
    """Ask the Gunicorn master to reload workers after a certificate refresh."""
    from hath.paths import get_config_dir

    try:
        pid_path = os.path.join(get_config_dir(), 'gunicorn.pid')
        with open(pid_path, 'r') as f:
            pid = int(f.read().strip())
        logger.info(f'Sending SIGUSR2 to Gunicorn master process... PID: {pid}')
        os.kill(pid, signal.SIGUSR2)
    except Exception as e:
        logger.error(f"Failed to restart Gunicorn: {e}")

