"""
Multiprocess HTTP server implementation.
"""

import ssl
import tempfile
import os
import queue
import time
import threading
from pathlib import Path
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
        # Set active client to None for HTTP server process
        from .settings import Settings
        Settings.set_active_client(None)
    
    def run(self):
        """Run the HTTP server."""
        try:
            Out.info("Starting multiprocess HTTPS server...")
            
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
        """Create HTTP server instance with SSL support."""
        from http.server import ThreadingHTTPServer
        
        # Get server configuration
        port = Settings.get_client_port()
        max_connections = Settings.get_int('max_connections', 100)
        
        Out.info(f"Creating HTTPS server on port {port} with max {max_connections} connections")
        
        # Create request handler class with shared resources
        def handler_factory(*args, **kwargs):
            return MultiprocessHTTPRequestHandler(self.shared, *args, **kwargs)
        
        # Create server
        self.server = ThreadingHTTPServer(
            ('', port),
            handler_factory
        )
        
        # Configure SSL/TLS
        if not self._configure_ssl():
            Out.error("Failed to configure SSL - multiprocess HTTP server will not start")
            raise Exception("SSL configuration failed")
        
        # Configure server
        self.server.timeout = 1.0  # Check for shutdown every second
        
        Out.info(f"HTTPS server created on port {port}")
    
    def _configure_ssl(self) -> bool:
        """Configure SSL/TLS for the multiprocess server."""
        try:
            # Check if we have SSL configuration in shared resources
            with self.shared.settings_lock:
                client_key = self.shared.client_settings.get('client_key')
                client_id = self.shared.client_settings.get('client_id')
                data_dir = self.shared.client_settings.get('data_dir', 'data')
            
            if not client_key or not client_id:
                Out.error("SSL configuration missing client credentials")
                return False
            
            # Get certificate paths
            data_path = Path(data_dir)
            p12_path = data_path / "client.p12"
            
            if not p12_path.exists():
                Out.error(f"SSL certificate not found at {p12_path}")
                Out.error("Certificate must be downloaded by main process before starting HTTP server")
                return False
            
            # Create SSL context
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            
            # Load PKCS#12 certificate directly
            try:
                if Path(p12_path).exists():
                    from cryptography.hazmat.primitives.serialization import pkcs12
                    from cryptography.hazmat.primitives import serialization
                    
                    # Read PKCS#12 data
                    with open(p12_path, 'rb') as f:
                        p12_data = f.read()
                    
                    # Try loading with different passwords - client key is the primary password
                    passwords_to_try = [
                        client_key.encode(),  # Most likely - client key
                        None, 
                        b'', 
                        str(client_id).encode(),
                        b'hentai@home'
                    ]
                    
                    private_key = None
                    certificate = None
                    additional_certificates = None
                    
                    for password in passwords_to_try:
                        try:
                            private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                                p12_data, password=password
                            )
                            Out.debug(f"Successfully loaded PKCS#12 for SSL with password: {'None' if password is None else 'provided'}")
                            break
                        except Exception as e:
                            Out.debug(f"Failed to load PKCS#12 for SSL with password attempt: {e}")
                            continue
                    
                    if not (private_key and certificate):
                        raise Exception("Could not load certificate and private key from PKCS#12")
                    
                    # Create temporary PEM files for SSL context (including full chain if available)
                    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.crt') as cert_file:
                        # Write the main certificate
                        cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
                        
                        # Add additional certificates to the chain if available
                        if additional_certificates:
                            for additional_cert in additional_certificates:
                                cert_file.write(additional_cert.public_bytes(serialization.Encoding.PEM))
                        
                        temp_cert_path = cert_file.name
                    
                    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as key_file:
                        key_file.write(private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        ))
                        temp_key_path = key_file.name
                    
                    # Load into SSL context
                    ssl_context.load_cert_chain(temp_cert_path, temp_key_path)
                    
                    # Clean up temporary files
                    try:
                        os.unlink(temp_cert_path)
                        os.unlink(temp_key_path)
                    except:
                        pass  # Ignore cleanup errors
                    
                    Out.debug("Loaded PKCS#12 certificate for SSL in multiprocess server")
                else:
                    raise FileNotFoundError("PKCS#12 certificate file not found")
                    
            except Exception as e:
                Out.error(f"Failed to configure SSL in multiprocess server: {e}")
                return False
            
            # Configure SSL settings for H@H
            ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            
            # Apply SSL context to server socket
            self.server.socket = ssl_context.wrap_socket(self.server.socket, server_side=True)
            
            Out.info("SSL/TLS configured successfully for multiprocess HTTP server")
            return True
            
        except Exception as e:
            Out.error(f"Failed to configure SSL for multiprocess server: {e}")
            return False
    
    def _serve_forever(self):
        """Serve HTTPS requests until shutdown."""
        Out.info("HTTPS server ready to accept connections")
        
        while not self.shutdown_flag and not self.shared.shutdown_event.is_set():
            try:
                self.server.handle_request()
            except OSError as e:
                if not self.shutdown_flag:
                    Out.warning(f"HTTPS server socket error: {e}")
                break
            except Exception as e:
                Out.warning(f"HTTPS server error: {e}")
                time.sleep(0.1)
    
    def _cleanup(self):
        """Cleanup server resources."""
        self.shutdown_flag = True
        
        if self.server:
            try:
                self.server.server_close()
                Out.info("HTTPS server closed")
            except Exception as e:
                Out.warning(f"Error closing HTTPS server: {e}")
        
        Out.info("HTTPS server cleanup complete")
