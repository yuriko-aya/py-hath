"""
Multiprocess HTTP server implementation.
"""

import queue
import time
import threading
from typing import Dict, Any

from .out import Out
from .settings import Settings
from .http_server import HTTPServer, HTTPRequestHandler
from .stats import Stats


class MultiprocessHTTPRequestHandler(HTTPRequestHandler):
    """HTTP request handler for multiprocess environment."""
    
    def __init__(self, shared_resources, *args, **kwargs):
        """Initialize with shared resources."""
        self.shared = shared_resources
        super().__init__(*args, **kwargs)
    
    def handle_request(self):
        """Override to use shared cache and stats."""
        # Send heartbeat
        try:
            self.shared.stats_queue.put({
                'type': 'heartbeat',
                'process': 'http_server',
                'timestamp': time.time()
            }, block=False)
        except queue.Full:
            pass  # Skip if queue is full
        
        # Call parent implementation
        super().handle_request()
    
    def serve_file_from_cache(self, hv_file):
        """Serve file with multiprocess stats tracking."""
        try:
            # Call parent implementation
            super().serve_file_from_cache(hv_file)
            
            # Update stats
            file_size = hv_file.size if hasattr(hv_file, 'size') else 0
            self.shared.stats_queue.put({
                'type': 'file_served',
                'file_id': hv_file.file_id if hasattr(hv_file, 'file_id') else 'unknown',
                'bytes': file_size,
                'timestamp': time.time()
            }, block=False)
            
        except queue.Full:
            # Continue serving even if stats queue is full
            pass
        except Exception as e:
            Out.warning(f"Error in multiprocess file serving: {e}")
    
    def get_cache_handler(self):
        """Get cache handler from shared resources."""
        return SharedCacheHandler(self.shared)


class SharedCacheHandler:
    """Cache handler that uses shared resources."""
    
    def __init__(self, shared_resources):
        """Initialize with shared resources."""
        self.shared = shared_resources
    
    def get_file_from_cache(self, file_id: str):
        """Get file from shared cache index."""
        with self.shared.cache_lock:
            file_info = self.shared.cache_index.get(file_id)
            if file_info:
                return self._create_hv_file_from_info(file_info)
            return None
    
    def _create_hv_file_from_info(self, file_info: Dict[str, Any]):
        """Create HVFile object from cached info."""
        from .cache_handler import HVFile
        return HVFile(
            file_info['file_id'],
            file_info['size'],
            file_info['hash']
        )
    
    def add_file_to_cache(self, hv_file, file_data: bytes = None):
        """Add file to shared cache index."""
        with self.shared.cache_lock:
            file_info = {
                'file_id': hv_file.file_id,
                'size': hv_file.size,
                'hash': hv_file.sha1_hash,
                'last_accessed': time.time()
            }
            self.shared.cache_index[hv_file.file_id] = file_info
            
            # Update cache stats
            self.shared.cache_stats['file_count'] = len(self.shared.cache_index)
            self.shared.cache_stats['last_update'] = time.time()
    
    def mark_recently_accessed(self, hv_file, is_new: bool = False):
        """Mark file as recently accessed."""
        with self.shared.cache_lock:
            if hv_file.file_id in self.shared.cache_index:
                self.shared.cache_index[hv_file.file_id]['last_accessed'] = time.time()
        return True


class MultiprocessHTTPServer:
    """HTTP server for multiprocess environment."""
    
    def __init__(self, shared_resources):
        """Initialize multiprocess HTTP server."""
        self.shared = shared_resources
        self.server = None
        self.shutdown_flag = False
        self.heartbeat_thread = None
        
        # Apply settings from shared resources
        self._apply_shared_settings()
    
    def _apply_shared_settings(self):
        """Apply settings from shared resources."""
        # Copy settings from shared resources to local Settings
        with self.shared.settings_lock:
            for key, value in self.shared.client_settings.items():
                Settings.set(key, value)
    
    def run(self):
        """Run the HTTP server."""
        try:
            Out.info("Starting multiprocess HTTP server...")
            
            # Start heartbeat thread
            self._start_heartbeat()
            
            # Create and configure HTTP server
            self._create_server()
            
            # Start serving
            self._serve_forever()
            
        except Exception as e:
            Out.error(f"HTTP server error: {e}")
            self.shared.command_queue.put({
                'type': 'shutdown_request',
                'process': 'http_server',
                'error': str(e)
            })
        finally:
            self._cleanup()
    
    def _start_heartbeat(self):
        """Start heartbeat thread."""
        def heartbeat_worker():
            while not self.shutdown_flag and not self.shared.shutdown_event.is_set():
                try:
                    self.shared.stats_queue.put({
                        'type': 'heartbeat',
                        'process': 'http_server',
                        'timestamp': time.time()
                    }, block=False)
                except queue.Full:
                    pass  # Skip if queue is full
                
                time.sleep(10)  # Send heartbeat every 10 seconds
        
        self.heartbeat_thread = threading.Thread(target=heartbeat_worker, daemon=True)
        self.heartbeat_thread.start()
    
    def _create_server(self):
        """Create HTTP server instance."""
        from http.server import ThreadingHTTPServer
        
        # Get server configuration
        port = Settings.get_client_port()
        max_connections = Settings.get_int('max_connections', 100)
        
        Out.info(f"Creating HTTP server on port {port} with max {max_connections} connections")
        
        # Create request handler class with shared resources
        def handler_factory(*args, **kwargs):
            return MultiprocessHTTPRequestHandler(self.shared, *args, **kwargs)
        
        # Create server
        self.server = ThreadingHTTPServer(
            ('', port),
            handler_factory
        )
        
        # Configure server
        self.server.timeout = 1.0  # Check for shutdown every second
        
        Out.info(f"HTTP server created on port {port}")
    
    def _serve_forever(self):
        """Serve HTTP requests until shutdown."""
        Out.info("HTTP server ready to accept connections")
        
        while not self.shutdown_flag and not self.shared.shutdown_event.is_set():
            try:
                self.server.handle_request()
            except OSError as e:
                if not self.shutdown_flag:
                    Out.warning(f"HTTP server socket error: {e}")
                break
            except Exception as e:
                Out.warning(f"HTTP server error: {e}")
                time.sleep(0.1)
    
    def _cleanup(self):
        """Cleanup server resources."""
        self.shutdown_flag = True
        
        if self.server:
            try:
                self.server.server_close()
                Out.info("HTTP server closed")
            except Exception as e:
                Out.warning(f"Error closing HTTP server: {e}")
        
        Out.info("HTTP server cleanup complete")
