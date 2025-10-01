import atexit
import cache_manager
import db_manager as db
import event_manager
import storage_manager
import download_manager
import logging
import socket
import signal
import time
import threading
import hashlib
import os
import sys
import rpc_manager
import config_manager

logger = logging.getLogger(__name__)

def notify_client_start() -> bool:
    """Notify the server that the client has started."""
    hath_config = config_manager.Config()
    try:
        current_acttime = config_manager.get_current_acttime()
        actkey = config_manager.generate_actkey("client_start")
        url_path = (f"/15/rpc?clientbuild={hath_config.client_build}&act=client_start"
                    f"&add=&cid={hath_config.client_id}&acttime={current_acttime}&actkey={actkey}")

        logger.debug("Notifying server that client has started...")
        response = rpc_manager._make_rpc_request(url_path, timeout=60)

        logger.debug("Server notification sent successfully")
        logger.debug(f"Server response: {response.text.strip()}")
        return True
        
    except Exception as e:
        logger.error(f"Error notifying server of client start: {e}")
        return False


def start_background_task():
    """Notify the server that the client has started - runs in background thread."""
    hath_config = config_manager.Config()

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
                    success = notify_client_start()              
                    if success:
                        hath_config.is_server_ready = True
                        deleted_blacklist = cache_manager.blacklist_process(259200)
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
    hath_config = config_manager.Config()

    def periodic_still_alive():
        counter = 1
        while True:
            try:
                # 2 minutes of each iterations
                time.sleep(120)
                if not hath_config.client_id or not hath_config.client_key:
                    logger.error("Configuration not available for still_alive notification")
                    continue
                
                # Generate still_alive notification URL
                current_acttime = config_manager.get_current_acttime()
                actkey_data = f"hentai@home-still_alive--{hath_config.client_id}-{current_acttime}-{hath_config.client_key}"
                actkey = hashlib.sha1(actkey_data.encode()).hexdigest()
                
                url_path = (
                    f"/15/rpc?clientbuild={hath_config.client_build}&act=still_alive"
                    f"&add=&cid={hath_config.client_id}&acttime={current_acttime}&actkey={actkey}"
                )
                
                logger.info("Sending periodic still_alive notification...")
                response = rpc_manager._make_rpc_request(url_path, timeout=10)

                logger.debug(f"Still_alive notification sent successfully: {response.text.strip()}")

                # Every 540 iterations (approximately every 18 hours), run blacklist cleanup
                if counter % 540 == 0:
                    deleted_blacklist = cache_manager.blacklist_process(43200)
                    logger.debug(f"Processed get_blacklist command, deleted {deleted_blacklist} files")
                counter += 1

                # Every 5 iteration (10 minutes), check if disk and cache size
                if counter % 5 == 0:
                    if not storage_manager.is_disk_ok():
                        sys.exit(0)

                    cache_manager.check_cache_size()

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
    hath_config = config_manager.Config()

    try:
        if not hath_config.client_id or not hath_config.client_key:
            logger.error("Configuration not available for client_stop notification")
            return
        
        logger.info("Sending client_stop notification...")
        
        # Generate client_stop notification URL
        current_acttime = config_manager.get_current_acttime()
        actkey_data = f"hentai@home-client_stop--{hath_config.client_id}-{current_acttime}-{hath_config.client_key}"
        actkey = hashlib.sha1(actkey_data.encode()).hexdigest()
        
        url_path = (
            f"/15/rpc?clientbuild={hath_config.client_build}&act=client_stop"
            f"&add=&cid={hath_config.client_id}&acttime={current_acttime}&actkey={actkey}"
        )

        response = rpc_manager._make_rpc_request(url_path, timeout=10)

        logger.debug(f"Client_stop notification sent successfully: {response.text.strip()}")
        
        # Clean up config cache when shutting down
        config_manager.remove_config()
        
        # Clean up database connections
        db.cleanup_connections()
        
    except Exception as e:
        logger.error(f"Failed to send client_stop notification: {e}")
        # Still try to clean up config cache even if notification failed
        config_manager.remove_config()
        # Clean up database connections
        db.cleanup_connections()


def setup_shutdown_handlers():
    """Setup signal handlers and atexit for graceful shutdown."""

    def signal_handler(signum, frame):
        """Handle shutdown signals."""
        try:
            signal_name = signal.Signals(signum).name if hasattr(signal, 'Signals') else str(signum)
            logger.info(f"Received signal {signal_name}, shutting down gracefully...")
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

