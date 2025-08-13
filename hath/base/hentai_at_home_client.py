"""
Main Hentai@Home client implementation in Python.
"""

import signal
import sys
import threading
import time
from typing import List, Optional

from .out import Out
from .settings import Settings
from .input_query_handler_cli import InputQueryHandlerCLI
from .stats import Stats


class HentaiAtHomeClient:
    """Main Hentai@Home client class."""
    
    def __init__(self, input_handler: InputQueryHandlerCLI, args: List[str]):
        """Initialize the Hentai@Home client."""
        self.input_handler = input_handler
        self.args = args
        self.shutdown_flag = False
        self.report_shutdown = False
        self.fast_shutdown = False
        self.thread_interruptable = False
        self.do_cert_refresh = False
        
        # Component instances
        self.http_server = None
        self.client_api = None
        self.cache_handler = None
        self.server_handler = None
        self.gallery_downloader = None
        
        # Threading
        self.main_thread = None
        self.thread_skip_counter = 0
        self.suspended_until = 0
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        Out.info(f"Received shutdown signal {signum}")
        
        # Try to save cache data immediately
        if self.cache_handler:
            try:
                self.cache_handler.save_cache_state()
                Out.info("Cache state saved before shutdown")
            except Exception as e:
                Out.error(f"Failed to save cache state during signal handling: {e}")
        
        self.shutdown()
    
    def run(self):
        """Main client execution method."""
        Settings.set_active_client(self)
        Settings.parse_args(self.args)  # Parse args first to get debug mode
        
        Out.start_loggers()  # Then start loggers with correct debug setting
        
        try:
            Settings.initialize_directories()
        except Exception as e:
            Out.error(f"Could not create program directories: {e}")
            sys.exit(1)
        
        Out.info(f"Hentai@Home Python {Settings.CLIENT_VERSION} (Build {Settings.CLIENT_BUILD}) starting up")
        Out.info("Copyright (c) 2008-2024, E-Hentai.org - all rights reserved.")
        Out.info("This software comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to modify and redistribute it under the GPL v3 license.")
        
        # Initialize statistics system
        Stats.reset_stats()
        Stats.set_program_status("Logging in to main server...")
        
        # Enable bytes sent history tracking for performance monitoring
        Stats.track_bytes_sent_history()
        
        # Load login credentials
        Settings.load_client_login_from_file()
        
        if not Settings.login_credentials_are_syntax_valid():
            Settings.prompt_for_id_and_key(self.input_handler)
        
        # Initialize components
        self._initialize_components()
        
        # Start main loop
        self._main_loop()
    
    def _initialize_components(self):
        """Initialize all client components."""
        Out.info("Initializing client components...")
        
        # Initialize client API for programmatic control
        from .client_api import ClientAPI
        self.client_api = ClientAPI(self)
        
        # Update stats
        Stats.set_program_status("Initializing client API...")
        
        # Initialize server handler
        from .server_handler import ServerHandler
        self.server_handler = ServerHandler(self)
        
        # Load client settings from server
        self.server_handler.load_client_settings_from_server()
        
        # Update stats
        Stats.set_program_status("Initializing cache handler...")
        
        # Initialize cache handler
        from .cache_handler import CacheHandler
        try:
            self.cache_handler = CacheHandler(self)
        except Exception as e:
            self.set_fast_shutdown()
            self.die_with_error(str(e))
            return
        
        if self.is_shutting_down():
            return
        
        # Update stats
        Stats.set_program_status("Starting HTTP server...")
        
        # Initialize HTTP server
        from .http_server import HTTPServer
        self.http_server = HTTPServer(self)
        
        if not self.http_server.start_connection_listener(Settings.get_client_port()):
            self.set_fast_shutdown()
            self.die_with_error("Failed to initialize HTTPServer")
            return
        
        # Update stats
        Stats.set_program_status("Sending startup notification...")
        
        # Notify server that startup is complete
        Out.info("Notifying the server that we have finished starting up the client...")
        
        if not self.server_handler.notify_start():
            self.set_fast_shutdown()
            Out.info("Startup notification failed.")
            return
        
        # Initialize gallery downloader for bulk downloads
        if Settings.get_bool('enable_gallery_downloader', True):
            Out.info("Starting gallery downloader...")
            from .gallery_downloader import GalleryDownloader
            try:
                self.gallery_downloader = GalleryDownloader(self)
                Out.info("Gallery downloader started successfully")
            except Exception as e:
                Out.warning(f"Failed to start gallery downloader: {e}")
                # Non-fatal error - continue without gallery downloader
        
        self.http_server.allow_normal_connections()
        self.report_shutdown = True
        
        # Update stats to running state
        Stats.program_started()
        Stats.set_program_status("Running normally")
        
        Out.info("Startup completed successfully. Starting normal operation")
    
    def _main_loop(self):
        """Main client operation loop."""
        last_thread_time = 0
        self.thread_skip_counter = 1
        
        while not self.shutdown_flag and not self.is_suspended():
            try:
                sleep_time = max(100, 30000 - (time.time() * 1000 - last_thread_time))
                
                Out.debug(f"Main thread sleeping for {sleep_time}ms")
                
                self.thread_interruptable = True
                time.sleep(sleep_time / 1000.0)
                self.thread_interruptable = False
                
                start_time = time.time() * 1000
                
                if not self.shutdown_flag and not self.is_suspended():
                    Out.debug("Main thread starting cycle")
                    
                    # Perform periodic tasks
                    self._perform_periodic_tasks()
                
                last_thread_time = start_time
                self.thread_skip_counter += 1
                
            except KeyboardInterrupt:
                Out.debug("Main thread sleep was interrupted")
                break
    
    def _perform_periodic_tasks(self):
        """Perform periodic maintenance tasks."""
        try:
            # Server communication
            if self.thread_skip_counter % 11 == 0:
                Out.debug("Performing server communication check...")
                if self.server_handler:
                    self.server_handler.still_alive_test(False)
            
            # Certificate management - check every 60 cycles (roughly every 30 minutes)
            if self.thread_skip_counter % 60 == 0:
                Out.debug("Checking certificate expiration...")
                if self.do_cert_refresh or (self.http_server and self.http_server.is_cert_expired()):
                    Out.info("SSL certificate expired or refresh requested, downloading new certificate...")
                    if self.server_handler and self.server_handler.download_certificate():
                        Out.info("SSL certificate refreshed successfully")
                        self.do_cert_refresh = False
                    else:
                        Out.error("Failed to refresh SSL certificate")
            
            # Cache maintenance
            if self.cache_handler:
                Out.debug("Performing cache maintenance...")
                self.cache_handler.cycle_lru_cache_table()
                
                # Save cache state periodically (every 30 cycles ~ 15 minutes)
                if self.thread_skip_counter % 30 == 0:
                    Out.debug("Saving cache state...")
                    self.cache_handler.save_cache_state()
                
                # Check free disk space
                Out.debug("Checking disk space...")
                prune_aggression = self.cache_handler.get_prune_aggression()
                Out.debug(f"Prune aggression: {prune_aggression}")
                for i in range(prune_aggression):
                    Out.debug(f"Disk space check iteration {i + 1}/{prune_aggression}")
                    if not self.cache_handler.recheck_free_disk_space():
                        Out.error("Disk is full. Shutting down to prevent damage.")
                        self.die_with_error("Out of disk space")
                        return
            
            # HTTP server maintenance
            if self.http_server:
                Out.debug("Performing HTTP server maintenance...")
                self.http_server.nuke_old_connections()
                
        except Exception as e:
            Out.error(f"Error in periodic tasks: {e}")
            raise
    
    def is_suspended(self) -> bool:
        """Check if the client is suspended."""
        # Ensure suspended_until is a valid number
        if self.suspended_until is None:
            self.suspended_until = 0
        return self.suspended_until > time.time() * 1000
    
    def suspend_master_thread(self, suspend_time: int) -> bool:
        """Suspend the master thread for the specified time in seconds."""
        if 0 < suspend_time <= 86400 and not self.is_suspended():
            suspend_time_millis = suspend_time * 1000
            self.suspended_until = time.time() * 1000 + suspend_time_millis
            Out.debug(f"Master thread suspended for {suspend_time} seconds.")
            
            # Update stats
            Stats.set_client_suspended(True)
            Stats.set_program_status(f"Suspended for {suspend_time} seconds")
            
            return self.server_handler.notify_suspend() if self.server_handler else True
        return False
    
    def resume_master_thread(self) -> bool:
        """Resume the master thread."""
        self.suspended_until = 0
        Out.debug("Master thread resumed.")
        
        # Update stats
        Stats.set_client_suspended(False)
        Stats.set_program_status("Running normally")
        
        # Notify server and test connection
        result = self.server_handler.notify_resume() if self.server_handler else True
        
        # Test server connection after resume (like Java client)
        if self.server_handler:
            self.server_handler.still_alive_test(True)  # resume=True
        
        return result
    
    def get_input_query_handler(self) -> InputQueryHandlerCLI:
        """Get the input query handler."""
        return self.input_handler
    
    def get_http_server(self):
        """Get the HTTP server instance."""
        return self.http_server
    
    def get_cache_handler(self):
        """Get the cache handler instance."""
        return self.cache_handler
    
    def get_server_handler(self):
        """Get the server handler instance."""
        return self.server_handler
    
    def is_shutting_down(self) -> bool:
        """Check if the client is shutting down."""
        return self.shutdown_flag
    
    def set_fast_shutdown(self):
        """Set fast shutdown flag."""
        Out.flush_logs()
        self.fast_shutdown = True
    
    def delete_downloader(self):
        """Clean up gallery downloader resources."""
        if self.gallery_downloader:
            try:
                Out.debug("Cleaning up gallery downloader resources...")
                self.gallery_downloader.shutdown()
                self.gallery_downloader = None
                Out.debug("Gallery downloader resources cleaned up successfully")
            except Exception as e:
                Out.warning(f"Error cleaning up gallery downloader resources: {e}")
        else:
            Out.debug("No gallery downloader to clean up")
    
    def shutdown(self):
        """Initiate client shutdown."""
        self._shutdown(False, None)
    
    def die_with_error(self, error: str):
        """Shutdown client with error message."""
        Out.error(f"Critical Error: {error}")
        self._shutdown(False, error)
    
    def _shutdown(self, from_shutdown_hook: bool, shutdown_error_message: Optional[str]):
        """Internal shutdown method."""
        Out.flush_logs()
        
        if not self.shutdown_flag:
            self.shutdown_flag = True
            Out.info("Shutting down...")
            
            if self.report_shutdown:
                if self.server_handler:
                    self.server_handler.notify_shutdown()
                
                if not self.fast_shutdown and self.http_server:
                    Out.info("Shutdown in progress - please wait up to 30 seconds")
                    self._http_server_shutdown(False)
            
            # Random shutdown message
            import random
            if random.random() > 0.99:
                Out.info("Goodbye! Thanks for running Hentai@Home!")
            else:
                messages = ["I don't hate you", "Whyyyyyyyy...", "No hard feelings", 
                           "Your business is appreciated", "Good-night"]
                Out.info(random.choice(messages))
            
            if self.cache_handler:
                self.cache_handler.terminate_cache()
            
            # Shutdown gallery downloader
            if self.gallery_downloader:
                try:
                    Out.info("Shutting down gallery downloader...")
                    self.gallery_downloader.shutdown()
                    Out.info("Gallery downloader shut down successfully")
                except Exception as e:
                    Out.warning(f"Error shutting down gallery downloader: {e}")
            
            if shutdown_error_message:
                Out.error(shutdown_error_message)
            
            Out.disable_logging()
        
        if not from_shutdown_hook:
            sys.exit(0)
    
    def _http_server_shutdown(self, restart: bool):
        """Shutdown the HTTP server."""
        try:
            time.sleep(5)
            
            if self.http_server:
                self.http_server.stop_connection_listener(restart)
                
                # Wait for connections to close
                close_wait_cycles = 0
                max_wait_cycles = 25
                
                while close_wait_cycles < max_wait_cycles:
                    # Check if there are open connections
                    open_connections = self.get_open_connections_count()
                    
                    if open_connections == 0:
                        break
                    
                    time.sleep(1)
                    close_wait_cycles += 1
                    
                    if close_wait_cycles % 5 == 0:
                        remaining_time = max_wait_cycles - close_wait_cycles
                        Out.info(f"Waiting for {open_connections} request(s) to finish; "
                               f"will wait for another {remaining_time} seconds")
        except Exception as e:
            Out.error(f"Error during HTTP server shutdown: {e}")
    
    @staticmethod
    def die_with_error_static(error: str):
        """Static method to die with error (for use before client is fully initialized)."""
        Out.error(f"Critical Error: {error}")
        sys.exit(1)
    
    def get_open_connections_count(self) -> int:
        """Get the number of currently open HTTP connections.
        
        Returns:
            Number of active HTTP sessions/connections
        """
        if self.http_server and hasattr(self.http_server, 'session_manager'):
            return self.http_server.session_manager.get_session_count()
        return 0
    
    def get_http_server(self):
        """Get the HTTP server instance."""
        return self.http_server
    
    def get_client_api(self):
        """Get the client API instance."""
        return self.client_api
