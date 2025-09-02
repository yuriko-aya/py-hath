import atexit
import cache_manager
import db_manager as db
import event_manager
import logging
import socket
import signal
import time
import threading
import hashlib
import os

from config_singleton import get_hath_config

logger = logging.getLogger(__name__)

def notify_server_startup():
    """Notify the server that the client has started - runs in background thread."""
    def wait_for_server_and_notify():
        # Wait for Flask server to be ready by checking if port is listening
        max_attempts = 30  # 30 seconds max wait
        attempts = 0
        
        hath_config = get_hath_config()
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
                        deleted_blacklist = cache_manager.blacklist_process(259200)
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
                hath_config = get_hath_config()
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
                    deleted_blacklist = cache_manager.blacklist_process(43200)
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
        hath_config = get_hath_config()
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
        
        # Clean up database connections
        db.cleanup_connections()
        
    except Exception as e:
        logger.error(f"Failed to send client_stop notification: {e}")
        # Still try to clean up config cache even if notification failed
        hath_config = get_hath_config()
        if hath_config:
            hath_config.cleanup_config_cache()
        # Clean up database connections
        db.cleanup_connections()


def setup_shutdown_handlers():
    """Setup signal handlers and atexit for graceful shutdown."""
    
    def signal_handler(signum, frame):
        """Handle shutdown signals."""
        try:
            signal_name = signal.Signals(signum).name if hasattr(signal, 'Signals') else str(signum)
            logger.info(f"Received signal {signal_name}, shutting down gracefully...")
            event_manager.stop_config_file_monitor()
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
            event_manager.stop_config_file_monitor()
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

