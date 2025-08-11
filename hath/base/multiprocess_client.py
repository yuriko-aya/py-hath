"""
Multiprocess Hentai@Home client implementation.
"""

import multiprocessing
import multiprocessing.managers
import queue
import signal
import sys
import time
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any

from .out import Out
from .settings import Settings
from .input_query_handler_cli import InputQueryHandlerCLI
from .stats import Stats


class SharedResources:
    """Manages shared resources between processes."""
    
    def __init__(self):
        """Initialize shared resources."""
        self.manager = multiprocessing.Manager()
        
        # Shared data structures
        self.cache_index = self.manager.dict()      # file_id -> file_info
        self.cache_stats = self.manager.dict()      # cache statistics
        self.client_settings = self.manager.dict()  # client configuration
        self.process_stats = self.manager.dict()    # per-process statistics
        
        # Locks for thread-safe operations
        self.cache_lock = multiprocessing.Lock()
        self.stats_lock = multiprocessing.Lock()
        self.settings_lock = multiprocessing.Lock()
        
        # Communication queues
        self.stats_queue = multiprocessing.Queue(maxsize=1000)
        self.download_queue = multiprocessing.Queue(maxsize=100)
        self.command_queue = multiprocessing.Queue(maxsize=50)
        self.response_queue = multiprocessing.Queue(maxsize=50)
        
        # Process control
        self.shutdown_event = multiprocessing.Event()
        self.processes_ready = self.manager.dict()
        
        # Initialize shared data
        self._initialize_shared_data()
    
    def _initialize_shared_data(self):
        """Initialize shared data structures."""
        # Cache statistics
        self.cache_stats.update({
            'file_count': 0,
            'total_size': 0,
            'last_update': time.time()
        })
        
        # Process status tracking
        self.process_stats.update({
            'main_process': {'status': 'starting', 'last_heartbeat': time.time()},
            'http_process': {'status': 'not_started', 'last_heartbeat': 0}
        })


class ProcessManager:
    """Manages process lifecycle and monitoring."""
    
    def __init__(self, shared_resources: SharedResources):
        """Initialize process manager."""
        self.shared = shared_resources
        self.processes = {}
        self.process_monitors = {}
        self.restart_attempts = {}
        self.max_restart_attempts = 3
        self.restart_delay = 5  # seconds
        
    def start_process(self, name: str, target, args: tuple = ()) -> bool:
        """Start a managed process."""
        try:
            process = multiprocessing.Process(
                target=target,
                args=args,
                name=f"hath_{name}"
            )
            process.start()
            
            self.processes[name] = process
            self.restart_attempts[name] = 0
            
            # Start monitor thread for this process
            monitor_thread = threading.Thread(
                target=self._monitor_process,
                args=(name,),
                daemon=True
            )
            monitor_thread.start()
            self.process_monitors[name] = monitor_thread
            
            Out.info(f"Started {name} process (PID: {process.pid})")
            return True
            
        except Exception as e:
            Out.error(f"Failed to start {name} process: {e}")
            return False
    
    def stop_process(self, name: str, timeout: int = 30) -> bool:
        """Stop a managed process gracefully."""
        if name not in self.processes:
            return True
        
        process = self.processes[name]
        
        try:
            # Signal graceful shutdown
            self.shared.shutdown_event.set()
            
            # Wait for graceful shutdown
            process.join(timeout=timeout)
            
            if process.is_alive():
                Out.warning(f"Process {name} did not shut down gracefully, terminating...")
                process.terminate()
                process.join(timeout=5)
                
                if process.is_alive():
                    Out.error(f"Process {name} did not terminate, killing...")
                    process.kill()
                    process.join()
            
            Out.info(f"Stopped {name} process")
            del self.processes[name]
            return True
            
        except Exception as e:
            Out.error(f"Error stopping {name} process: {e}")
            return False
    
    def _monitor_process(self, name: str):
        """Monitor a process and restart if needed."""
        while name in self.processes and not self.shared.shutdown_event.is_set():
            process = self.processes[name]
            
            # Check if process is still alive
            if not process.is_alive():
                Out.warning(f"Process {name} died unexpectedly")
                
                # Check restart attempts
                if self.restart_attempts[name] < self.max_restart_attempts:
                    self.restart_attempts[name] += 1
                    Out.info(f"Attempting to restart {name} (attempt {self.restart_attempts[name]})")
                    
                    # Wait before restart
                    time.sleep(self.restart_delay)
                    
                    # Restart process
                    if self._restart_process(name):
                        Out.info(f"Successfully restarted {name}")
                    else:
                        Out.error(f"Failed to restart {name}")
                        break
                else:
                    Out.error(f"Process {name} failed too many times, giving up")
                    break
            
            time.sleep(5)  # Check every 5 seconds
    
    def _restart_process(self, name: str) -> bool:
        """Restart a failed process."""
        # This is a simplified restart - in a full implementation,
        # we would need to restore the process state properly
        return False  # Placeholder
    
    def stop_all_processes(self):
        """Stop all managed processes."""
        Out.info("Stopping all processes...")
        
        # Signal shutdown to all processes
        self.shared.shutdown_event.set()
        
        # Stop each process
        for name in list(self.processes.keys()):
            self.stop_process(name)
        
        Out.info("All processes stopped")


class MultiprocessHentaiAtHomeClient:
    """Multiprocess Hentai@Home client."""
    
    def __init__(self, input_handler: InputQueryHandlerCLI, args: List[str]):
        """Initialize the multiprocess client."""
        self.input_handler = input_handler
        self.args = args
        self.shutdown_flag = False
        
        # Shared resources and process management
        self.shared = SharedResources()
        self.process_manager = ProcessManager(self.shared)
        
        # Component instances (local to main process)
        self.server_handler = None
        self.stats_collector = None
        
        # Track server notifications to prevent duplicates
        self.startup_notified = False
        self.shutdown_notified = False
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        Out.info(f"Received shutdown signal {signum}")
        self.shutdown()
    
    def run(self):
        """Main client execution method."""
        Settings.set_active_client(self)
        Settings.parse_args(self.args)
        
        Out.start_loggers()
        
        try:
            Settings.initialize_directories()
        except Exception as e:
            Out.error(f"Could not create program directories: {e}")
            sys.exit(1)
        
        Out.info(f"Hentai@Home Python Multiprocess {Settings.CLIENT_VERSION} starting up")
        Out.info("Multiprocess mode: Enhanced performance and reliability")
        
        # Initialize statistics system
        Stats.reset_stats()
        Stats.set_program_status("Initializing multiprocess client...")
        
        # Initialize download manager attribute
        self.gallery_downloader = None
        
        try:
            self._initialize_components()
            self._start_processes()
            self._main_loop()
        except Exception as e:
            Out.error(f"Critical error in main process: {e}")
            self.shutdown()
    
    def _initialize_components(self):
        """Initialize main process components."""
        Out.info("Initializing main process components...")
        
        # Load client settings
        Settings.load_client_login_from_file()
        
        if not Settings.login_credentials_are_syntax_valid():
            Settings.prompt_for_id_and_key(self.input_handler)
        
        # Initialize server handler in main process
        from .server_handler import ServerHandler
        self.server_handler = ServerHandler(self)
        
        # Load settings from server
        self.server_handler.load_client_settings_from_server()
        
        # Ensure SSL certificate is available before starting HTTP server
        if not self.server_handler.is_certificate_valid():
            Out.info("SSL certificate invalid or missing, downloading from server...")
            if not self.server_handler.download_certificate():
                Out.error("Failed to download SSL certificate")
                self.die_with_error("SSL certificate required for HTTPS server")
        
        # Share SSL configuration with HTTP server process
        with self.shared.settings_lock:
            self.shared.client_settings.update({
                'client_key': Settings.get_client_key(),
                'client_id': Settings.get_client_id(),
                'data_dir': str(Settings.get_data_dir()),
                'client_port': Settings.get_client_port()
            })
        
        # Start stats collector
        self._start_stats_collector()
        
        Out.info("Main process components initialized")
    
    def _start_stats_collector(self):
        """Start the statistics collector thread."""
        def stats_collector_worker():
            """Collect statistics from all processes."""
            while not self.shutdown_flag:
                try:
                    # Collect stats from queue with timeout
                    try:
                        stat_update = self.shared.stats_queue.get(timeout=1.0)
                        self._process_stat_update(stat_update)
                    except queue.Empty:
                        continue
                except Exception as e:
                    Out.warning(f"Error in stats collector: {e}")
                    time.sleep(1)
        
        self.stats_collector = threading.Thread(
            target=stats_collector_worker,
            daemon=True
        )
        self.stats_collector.start()
        Out.debug("Statistics collector started")
    
    def _process_stat_update(self, stat_update: Dict[str, Any]):
        """Process a statistics update from a worker process."""
        try:
            stat_type = stat_update.get('type')
            
            if stat_type == 'file_served':
                Stats.get_instance().increment_files_sent()
                Stats.get_instance().add_bytes_sent(stat_update.get('bytes', 0))
            elif stat_type == 'file_received':
                Stats.get_instance().increment_files_received()
                Stats.get_instance().add_bytes_received(stat_update.get('bytes', 0))
            elif stat_type == 'cache_update':
                with self.shared.cache_lock:
                    self.shared.cache_stats['file_count'] = stat_update.get('file_count', 0)
                    self.shared.cache_stats['total_size'] = stat_update.get('total_size', 0)
            elif stat_type == 'heartbeat':
                process_name = stat_update.get('process', 'unknown')
                with self.shared.stats_lock:
                    if process_name in self.shared.process_stats:
                        self.shared.process_stats[process_name]['last_heartbeat'] = time.time()
                        self.shared.process_stats[process_name]['status'] = 'running'
            
        except Exception as e:
            Out.warning(f"Error processing stat update: {e}")
    
    def _start_processes(self):
        """Start worker processes."""
        Out.info("Starting HTTP server process...")
        
        # Start only HTTP server process
        if not self.process_manager.start_process(
            'http_server',
            http_server_process_main,
            (self.shared,)
        ):
            self.die_with_error("Failed to start HTTP server process")
            return
        
        # Download manager runs in main process - initialize it here
        self._initialize_gallery_downloader()
        
        # Wait for HTTP server process to be ready
        self._wait_for_processes_ready()
        
        Out.info("HTTP server process started successfully")
    
    def _initialize_gallery_downloader(self):
        """Initialize gallery downloader in main process."""
        try:
            if Settings.get_bool('enable_gallery_downloader', True):
                from .gallery_downloader import GalleryDownloader
                self.gallery_downloader = GalleryDownloader(self)
                Out.info("Gallery downloader initialized in main process")
            else:
                Out.info("Gallery downloader disabled in settings")
        except Exception as e:
            Out.warning(f"Failed to initialize gallery downloader: {e}")
            self.gallery_downloader = None
    
    def _wait_for_processes_ready(self, timeout: int = 30):
        """Wait for HTTP server process to report ready."""
        start_time = time.time()
        required_processes = {'http_server'}  # Only HTTP server now
        
        while time.time() - start_time < timeout:
            ready_processes = set(self.shared.processes_ready.keys())
            if required_processes.issubset(ready_processes):
                Out.info("HTTP server process is ready")
                return
            
            missing = required_processes - ready_processes
            Out.debug(f"Waiting for processes: {missing}")
            time.sleep(1)
        
        self.die_with_error("Timeout waiting for HTTP server process to be ready")
    
    def _main_loop(self):
        """Main process control loop."""
        Out.info("Starting main control loop")
        
        # Notify server of startup completion
        if self.server_handler and not self.startup_notified:
            if self.server_handler.notify_start():
                self.startup_notified = True
                Out.info("Server notified of startup")
            else:
                Out.warning("Failed to notify server of startup")
        
        # Update status
        Stats.set_program_status("Running in multiprocess mode")
        
        # Set flag to prevent child processes from sending notifications
        self.shared.client_settings['is_main_process'] = True
        
        last_maintenance = 0
        maintenance_interval = 30  # seconds
        
        while not self.shutdown_flag:
            try:
                current_time = time.time()
                
                # Perform periodic maintenance
                if current_time - last_maintenance > maintenance_interval:
                    self._perform_maintenance()
                    last_maintenance = current_time
                
                # Process download requests in main process
                self._process_downloads()
                
                # Process commands from worker processes
                self._process_commands()
                
                # Check process health
                self._check_process_health()
                
                time.sleep(5)  # Main loop iteration delay
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                Out.error(f"Error in main loop: {e}")
                time.sleep(1)
    
    def _perform_maintenance(self):
        """Perform periodic maintenance tasks."""
        try:
            # Server communication
            if self.server_handler:
                self.server_handler.still_alive_test(False)
            
            # Download manager maintenance
            if self.gallery_downloader:
                # Perform any gallery downloader maintenance here
                pass
            
            # Send heartbeat
            self.shared.stats_queue.put({
                'type': 'heartbeat',
                'process': 'main_process',
                'timestamp': time.time()
            })
            
        except Exception as e:
            Out.warning(f"Error in maintenance: {e}")
    
    def _process_downloads(self):
        """Process download requests from the download queue."""
        if not self.gallery_downloader:
            return
        
        try:
            # Process download requests from queue
            while not self.shared.download_queue.empty():
                try:
                    download_request = self.shared.download_queue.get_nowait()
                    self._handle_download_request(download_request)
                except queue.Empty:
                    break
        except Exception as e:
            Out.warning(f"Error processing downloads: {e}")
    
    def _handle_download_request(self, request: Dict[str, Any]):
        """Handle a download request in the main process."""
        try:
            # Extract download parameters
            gid = request.get('gid')
            page = request.get('page')
            
            if gid and page and self.gallery_downloader:
                # Process download using the gallery downloader
                # Note: This is a simplified implementation
                # The actual gallery downloader may have different methods
                Out.debug(f"Processing download request for gallery {gid} page {page}")
                
                # Update stats if successful
                # This would need to be implemented based on actual GalleryDownloader API
                
        except Exception as e:
            Out.warning(f"Error handling download request: {e}")
    
    def _process_commands(self):
        """Process commands from worker processes."""
        try:
            while not self.shared.command_queue.empty():
                try:
                    command = self.shared.command_queue.get_nowait()
                    self._handle_command(command)
                except queue.Empty:
                    break
        except Exception as e:
            Out.warning(f"Error processing commands: {e}")
    
    def _handle_command(self, command: Dict[str, Any]):
        """Handle a command from a worker process."""
        cmd_type = command.get('type')
        
        if cmd_type == 'shutdown_request':
            Out.info("Shutdown requested by worker process")
            self.shutdown()
        elif cmd_type == 'restart_request':
            process_name = command.get('process', 'unknown')
            Out.info(f"Restart requested for {process_name}")
            # Handle restart logic here
        elif cmd_type == 'settings_request':
            # Send current settings to requesting process
            response = {
                'type': 'settings_response',
                'settings': dict(self.shared.client_settings)
            }
            self.shared.response_queue.put(response)
    
    def _check_process_health(self):
        """Check health of all worker processes."""
        current_time = time.time()
        health_timeout = 60  # seconds
        
        with self.shared.stats_lock:
            for process_name, stats in self.shared.process_stats.items():
                if process_name == 'main_process':
                    continue
                
                last_heartbeat = stats.get('last_heartbeat', 0)
                if current_time - last_heartbeat > health_timeout:
                    Out.warning(f"Process {process_name} has not sent heartbeat for {current_time - last_heartbeat:.1f}s")
    
    def shutdown(self):
        """Shutdown the multiprocess client."""
        if self.shutdown_flag:
            return
        
        Out.info("Shutting down multiprocess client...")
        self.shutdown_flag = True
        
        # Notify server of shutdown
        if self.server_handler and not self.shutdown_notified:
            try:
                if self.server_handler.notify_shutdown():
                    self.shutdown_notified = True
                    Out.info("Server notified of shutdown")
                else:
                    Out.warning("Failed to notify server of shutdown")
            except Exception as e:
                Out.warning(f"Error notifying server of shutdown: {e}")
        
        # Shutdown gallery downloader
        if self.gallery_downloader:
            try:
                Out.info("Shutting down gallery downloader...")
                self.gallery_downloader.shutdown()
                Out.info("Gallery downloader shut down successfully")
            except Exception as e:
                Out.warning(f"Error shutting down gallery downloader: {e}")
        
        # Stop all worker processes
        self.process_manager.stop_all_processes()
        
        Out.info("Multiprocess client shutdown complete")
    
    def die_with_error(self, error: str):
        """Shutdown with error message."""
        Out.error(f"Critical Error: {error}")
        self.shutdown()
        sys.exit(1)
    
    # Compatibility methods for existing code
    def get_server_handler(self):
        """Get the server handler instance."""
        return self.server_handler
    
    def get_cache_handler(self):
        """Get the cache handler instance (shared resource)."""
        return None  # Cache is managed by shared resources
    
    def get_download_manager(self):
        """Get the download manager instance (gallery downloader)."""
        return self.gallery_downloader
    
    def get_gallery_downloader(self):
        """Get the gallery downloader instance."""
        return self.gallery_downloader
    
    def get_http_server(self):
        """Get the HTTP server instance (runs in separate process)."""
        return None  # HTTP server runs in separate process
    
    def is_shutting_down(self) -> bool:
        """Check if client is shutting down."""
        return self.shutdown_flag


def http_server_process_main(shared_resources: SharedResources):
    """Main function for HTTP server process."""
    try:
        # Set up logging for this process
        Out.setup_process_logging("http_server")
        Out.info("HTTP server process starting...")
        
        # IMPORTANT: Clear active client to prevent duplicate server notifications
        # Only the main process should send server notifications
        Settings.set_active_client(None)
        
        # Import in process to avoid import issues
        from .multiprocess_http_server import MultiprocessHTTPServer
        
        # Create HTTP server
        server = MultiprocessHTTPServer(shared_resources)
        
        # Signal that process is ready
        shared_resources.processes_ready['http_server'] = True
        
        # Start server
        server.run()
        
    except Exception as e:
        Out.error(f"HTTP server process error: {e}")
        shared_resources.command_queue.put({
            'type': 'shutdown_request',
            'process': 'http_server',
            'error': str(e)
        })
    finally:
        Out.info("HTTP server process exiting")
