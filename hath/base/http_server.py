"""
HTTP server for serving cached files and handling requests.
"""

import ssl
import socket
import threading
import time
from pathlib import Path
from http.server import HTTPServer as BaseHTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from .out import Out
from .settings import Settings


class HTTPRequestHandler(BaseHTTPRequestHandler):
    """Custom HTTP request handler for Hentai@Home."""
    
    def __init__(self, *args, **kwargs):
        self.hath_server = None
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests."""
        try:
            self.handle_request()
        except Exception as e:
            Out.error(f"Error handling request: {e}")
            self.send_error(500, "Internal Server Error")
    
    def do_HEAD(self):
        """Handle HEAD requests."""
        try:
            self.handle_request()
        except Exception as e:
            Out.error(f"Error handling HEAD request: {e}")
            self.send_error(500, "Internal Server Error")
    
    def handle_request(self):
        """Handle HTTP request."""
        # Parse URL - match Java's URL processing
        parsed_url = urlparse(self.path)
        
        # Java: requestParts[1] = absoluteUriPattern.matcher(requestParts[1]).replaceFirst("/");
        # Java: String[] urlparts = requestParts[1].replace("%3d", "=").split("/");
        url_path = parsed_url.path.replace("%3d", "=")
        urlparts = url_path.split('/')
        
        Out.debug(f"Request path: {self.path}")
        Out.debug(f"URL parts: {urlparts}")
        Out.debug(f"URL parts length: {len(urlparts)}")
        
        # Java validation: if( (urlparts.length < 2) || !urlparts[0].equals("")) 
        if len(urlparts) < 2 or urlparts[0] != "":
            Out.debug("The requested URL is invalid or not supported.")
            self.send_error(404, "Invalid URL")
            return
        
        # Handle root path case - when there's only "/" path
        if len(urlparts) == 2 and urlparts[1] == "":
            self.send_status_page()
            return
        
        request_type = urlparts[1]
        Out.debug(f"Request type: '{request_type}'")
        
        # Handle different request types based on Java parseRequest logic
        if request_type == 'h':
            # Java: form: /h/$fileid/$additional/$filename
            # Java: if(urlparts.length < 4)
            if len(urlparts) < 4:
                self.send_error(400, "Bad Request")
                return
            Out.debug("Handling file request")
            self.handle_file_request(urlparts)
            return
            
        elif request_type == 'servercmd':
            # Java: form: /servercmd/$command/$additional/$time/$key
            # Java: if(urlparts.length < 6)
            if len(urlparts) < 6:
                Out.debug("Got a malformed servercmd")
                self.send_error(403, "Malformed servercmd")
                return
            Out.debug("Handling server command")
            self.handle_server_command(urlparts)
            return
            
        elif request_type == 't':
            # Java: form: /t/$testsize/$testtime/$testkey
            # Java: if(urlparts.length < 5)
            if len(urlparts) < 5:
                self.send_error(400, "Bad Request")
                return
            Out.debug("Handling speed test")
            self.handle_speedtest_request(urlparts)
            return
            
        elif len(urlparts) == 2:
            # Java: else if(urlparts.length == 2)
            if request_type == 'favicon.ico':
                # Java: Redirect to the main website icon
                self.send_response(301)  # Moved Permanently
                self.send_header('Location', 'https://e-hentai.org/favicon.ico')
                self.end_headers()
                return
            elif request_type == 'robots.txt':
                # Java: Bots are not welcome
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'User-agent: *\nDisallow: /')
                return
        
        # Default case - Java: Out.debug(session + " Invalid request type '" + urlparts[1]);
        Out.debug(f"Invalid request type '{request_type}'")
        self.send_error(404, "Not Found")
    
    def handle_file_request(self, urlparts: List[str]):
        """Handle file serving request."""
        try:
            # Java format: /h/$fileid/$additional/$filename
            # urlparts[0] = "", urlparts[1] = "h", urlparts[2] = fileid, urlparts[3] = additional
            fileid = urlparts[2]
            additional_str = urlparts[3]
            
            # Java: Hashtable<String,String> additional = Tools.parseAdditional(urlparts[3]);
            from .tools import Tools
            additional = Tools.parse_additional(additional_str)
            
            # Java: boolean keystampRejected = true;
            keystamp_rejected = True
            
            try:
                # Java keystamp validation logic
                keystamp = additional.get('keystamp', '')
                keystamp_parts = keystamp.split('-')
                
                if len(keystamp_parts) == 2:
                    keystamp_time = int(keystamp_parts[0])
                    
                    # Java: if(Math.abs(Settings.getServerTime() - keystampTime) < 900)
                    if abs(Settings.get_server_time() - keystamp_time) < 900:
                        # Java: keystampParts[1].equalsIgnoreCase(Tools.getSHA1String(keystampTime + "-" + fileid + "-" + Settings.getClientKey() + "-hotlinkthis").substring(0, 10))
                        expected_key = Tools.get_sha1_string(f"{keystamp_time}-{fileid}-{Settings.get_client_key()}-hotlinkthis")[:10]
                        if keystamp_parts[1].lower() == expected_key.lower():
                            keystamp_rejected = False
            except Exception:
                pass  # Java: catch(Exception e) {}
            
            # Java: String fileindex = additional.get("fileindex");
            # Java: String xres = additional.get("xres");
            fileindex = additional.get('fileindex')
            xres = additional.get('xres')
            
            if keystamp_rejected:
                # Java: responseStatusCode = 403;
                self.send_error(403, "Forbidden")
                return
            elif fileindex is None or xres is None:
                # Java: requestedHVFile == null || fileindex == null || xres == null || ...
                Out.debug("Invalid or missing arguments.")
                self.send_error(404, "Invalid or missing arguments")
                return
            elif not fileindex.isdigit() or not (xres == 'org' or xres.isdigit()):
                # Java: !Pattern.matches("^\\d+$", fileindex) || !Pattern.matches("^org|\\d+$", xres)
                Out.debug("Invalid fileindex or xres format.")
                self.send_error(404, "Invalid arguments")
                return
            
            # Get client instance
            client = Settings.get_active_client()
            if not client:
                self.send_error(500, "Server not ready")
                return
            
            cache_handler = client.get_cache_handler()
            if not cache_handler:
                self.send_error(500, "Cache not ready")
                return
            
            # Try to get file from cache
            hv_file = cache_handler.get_file_from_cache(fileid)
            
            if hv_file and hv_file.is_valid():
                # Serve from cache
                self.serve_file_from_cache(hv_file)
            else:
                # Try to fetch from server
                self.serve_file_via_proxy(fileindex, xres, fileid)
        
        except Exception as e:
            Out.error(f"Error handling file request: {e}")
            self.send_error(500, "Internal Server Error")
    
    def serve_file_from_cache(self, hv_file):
        """Serve a file from local cache."""
        try:
            file_path = hv_file.get_local_file_ref()
            
            if not file_path.exists():
                self.send_error(404, "File not found")
                return
            
            # Determine content type
            content_type = self.guess_content_type(file_path.name)
            
            # Send headers
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(hv_file.size))
            self.send_header('Accept-Ranges', 'bytes')
            self.end_headers()
            
            # Send file content (only for GET, not HEAD)
            if self.command == 'GET':
                with open(file_path, 'rb') as f:
                    while True:
                        data = f.read(8192)
                        if not data:
                            break
                        self.wfile.write(data)
            
            # Mark as recently accessed
            cache_handler = Settings.get_active_client().get_cache_handler()
            if cache_handler:
                cache_handler.mark_recently_accessed(hv_file)
            
        except Exception as e:
            Out.error(f"Error serving file from cache: {e}")
            self.send_error(500, "Internal Server Error")
    
    def serve_file_via_proxy(self, fileindex: str, xres: str, file_id: str):
        """Serve a file by proxying from the server."""
        try:
            # Get server handler
            client = Settings.get_active_client()
            server_handler = client.get_server_handler()
            
            if not server_handler:
                self.send_error(500, "Server handler not available")
                return
            
            # Get fetch URLs
            sources = server_handler.get_static_range_fetch_url(fileindex, xres, file_id)
            
            if not sources:
                self.send_error(404, "File not available")
                return
            
            # For now, send a simple response indicating proxy mode
            # In a full implementation, this would stream the file from the source
            self.send_response(502)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Proxy mode not fully implemented')
            
        except Exception as e:
            Out.error(f"Error serving file via proxy: {e}")
            self.send_error(500, "Internal Server Error")
    
    def handle_speedtest_request(self, urlparts: List[str]):
        """Handle speed test request."""
        try:
            # Java format: /t/$testsize/$testtime/$testkey
            # urlparts[0] = "", urlparts[1] = "t", urlparts[2] = testsize, urlparts[3] = testtime, urlparts[4] = testkey
            testsize = int(urlparts[2])
            testtime = int(urlparts[3])
            testkey = urlparts[4]
            
            # Java: if(Math.abs(testtime - Settings.getServerTime()) > Settings.MAX_KEY_TIME_DRIFT)
            if abs(testtime - Settings.get_server_time()) > Settings.MAX_KEY_TIME_DRIFT:
                Out.debug("Got a speedtest request with expired key")
                self.send_error(403, "Expired key")
                return
            
            # Java: if(!Tools.getSHA1String("hentai@home-speedtest-" + testsize + "-" + testtime + "-" + Settings.getClientID() + "-" + Settings.getClientKey()).equals(testkey))
            from .tools import Tools
            expected_key = Tools.get_sha1_string(f"hentai@home-speedtest-{testsize}-{testtime}-{Settings.get_client_id()}-{Settings.get_client_key()}")
            
            if expected_key != testkey:
                Out.debug("Got a speedtest request with invalid key")
                self.send_error(403, "Invalid key")
                return
            
            Out.debug(f"Sending speedtest with testsize={testsize} testtime={testtime} testkey={testkey}")
            
            # Java: responseStatusCode = 200; hpc = new HTTPResponseProcessorSpeedtest(testsize);
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(testsize))
            self.end_headers()
            
            if self.command == 'GET':
                # Send random test data (matching Java HTTPResponseProcessorSpeedtest)
                import random
                random_length = 8192
                random_bytes = bytes([random.randint(0, 255) for _ in range(random_length)])
                
                remaining = testsize
                while remaining > 0:
                    # Java: int bytecount = Math.min(getContentLength() - writeoff, Settings.TCP_PACKET_SIZE);
                    # Java: int startbyte = (int) Math.floor(Math.random() * (randomLength - bytecount));
                    current_chunk = min(remaining, 8192)
                    start_byte = random.randint(0, max(0, random_length - current_chunk))
                    
                    # Send a chunk from random position in our random data
                    if current_chunk <= random_length:
                        chunk_data = random_bytes[start_byte:start_byte + current_chunk]
                    else:
                        # For larger chunks, repeat the random data
                        chunk_data = (random_bytes * ((current_chunk // random_length) + 1))[:current_chunk]
                    
                    self.wfile.write(chunk_data)
                    remaining -= current_chunk
        
        except Exception as e:
            Out.error(f"Error handling speedtest request: {e}")
            self.send_error(500, "Internal Server Error")
    
    def handle_server_command(self, urlparts: List[str]):
        """Handle server command requests."""
        try:
            # Validate that the request comes from an authorized RPC server
            # Java: if(!Settings.isValidRPCServer(session.getSocketInetAddress()))
            client_ip = self.client_address[0]
            if not self.is_valid_rpc_server(client_ip):
                Out.debug(f"Got a servercmd from an unauthorized IP address: {client_ip}")
                self.send_error(403, "Unauthorized IP")
                return
            
            # Java format: /servercmd/$command/$additional/$time/$key
            # urlparts[0] = "", urlparts[1] = "servercmd", urlparts[2] = command, urlparts[3] = additional, urlparts[4] = time, urlparts[5] = key
            command = urlparts[2]
            additional = urlparts[3]
            command_time = int(urlparts[4])
            key = urlparts[5]
            
            Out.debug(f"Server command: command={command}, additional='{additional}', time={command_time}, key={key}")
            
            # Validate timestamp - Java: Math.abs(commandTime - Settings.getServerTime()) > Settings.MAX_KEY_TIME_DRIFT
            current_time = Settings.get_server_time()
            time_diff = abs(command_time - current_time)
            if time_diff > Settings.MAX_KEY_TIME_DRIFT:
                Out.debug(f"Got a servercmd with expired key: time_diff={time_diff}, max={Settings.MAX_KEY_TIME_DRIFT}")
                self.send_error(403, "Expired key")
                return
            
            # Validate key using exact Java format: 
            # Tools.getSHA1String("hentai@home-servercmd-" + command + "-" + additional + "-" + Settings.getClientID() + "-" + commandTime + "-" + Settings.getClientKey())
            from .tools import Tools
            expected_key = Tools.get_sha1_string(f"hentai@home-servercmd-{command}-{additional}-{Settings.get_client_id()}-{command_time}-{Settings.get_client_key()}")
            
            if not expected_key == key:
                Out.debug(f"Got a servercmd with incorrect key: expected={expected_key}, got={key}")
                self.send_error(403, "Invalid key")
                return
            
            # Process the command (based on Java processRemoteAPICommand)
            if command == 'still_alive':
                # Java: return new HTTPResponseProcessorText("I feel FANTASTIC and I'm still alive");
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'I feel FANTASTIC and I\'m still alive')
                Out.debug("Responded to server still_alive check")
                
            elif command == 'speed_test':
                # Java: String testsize = addTable.get("testsize");
                # Java: return new HTTPResponseProcessorSpeedtest(testsize != null ? Integer.parseInt(testsize) : 1000000);
                from .tools import Tools
                add_table = Tools.parse_additional(additional)
                testsize_str = add_table.get('testsize')
                testsize = int(testsize_str) if testsize_str else 1000000
                
                Out.debug(f"Sending servercmd speedtest with testsize={testsize}")
                
                # Send speed test data (matching HTTPResponseProcessorSpeedtest)
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Length', str(testsize))
                self.end_headers()
                
                if self.command == 'GET':
                    # Send random test data (matching Java HTTPResponseProcessorSpeedtest)
                    import random
                    random_length = 8192
                    random_bytes = bytes([random.randint(0, 255) for _ in range(random_length)])
                    
                    remaining = testsize
                    while remaining > 0:
                        current_chunk = min(remaining, 8192)
                        start_byte = random.randint(0, max(0, random_length - current_chunk))
                        
                        # Send a chunk from random position in our random data
                        if current_chunk <= random_length:
                            chunk_data = random_bytes[start_byte:start_byte + current_chunk]
                        else:
                            # For larger chunks, repeat the random data
                            chunk_data = (random_bytes * ((current_chunk // random_length) + 1))[:current_chunk]
                        
                        self.wfile.write(chunk_data)
                        remaining -= current_chunk
                
                Out.debug("Responded to server speed_test command")
                
            elif command == 'refresh_settings':
                # Java: client.getServerHandler().refreshServerSettings();
                # Java: return new HTTPResponseProcessorText("");
                client = Settings.get_active_client()
                if client:
                    server_handler = client.get_server_handler()
                    if server_handler:
                        try:
                            server_handler.refresh_server_settings()
                            Out.debug("Server settings refreshed")
                        except Exception as e:
                            Out.warning(f"Failed to refresh server settings: {e}")
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'')
                Out.debug("Responded to server refresh_settings command")
                
            elif command == 'threaded_proxy_test':
                # Java: return processThreadedProxyTest(addTable);
                # For now, return a placeholder response
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'OK:0-0')  # Format: OK:successfulTests-totalTimeMillis
                Out.debug("Responded to server threaded_proxy_test command")
                
            elif command == 'start_downloader':
                # Java: client.startDownloader();
                # Java: return new HTTPResponseProcessorText("");
                client = Settings.get_active_client()
                if client:
                    try:
                        # Start downloader (placeholder for now)
                        Out.debug("Start downloader requested")
                    except Exception as e:
                        Out.warning(f"Failed to start downloader: {e}")
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'')
                Out.debug("Responded to server start_downloader command")
                
            elif command == 'refresh_certs':
                # Java: client.setCertRefresh();
                # Java: return new HTTPResponseProcessorText("");
                client = Settings.get_active_client()
                if client:
                    try:
                        # Refresh certificates (placeholder for now)
                        Out.debug("Certificate refresh requested")
                    except Exception as e:
                        Out.warning(f"Failed to refresh certificates: {e}")
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'')
                Out.debug("Responded to server refresh_certs command")
                
            else:
                # Java: return new HTTPResponseProcessorText("INVALID_COMMAND");
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'INVALID_COMMAND')
                Out.debug(f"Unknown server command: {command}")
            
        except Exception as e:
            Out.error(f"Error handling server command: {e}")
            self.send_error(500, "Internal Server Error")
    
    def is_valid_rpc_server(self, client_ip: str) -> bool:
        """Check if the client IP is from a valid RPC server."""
        # For now, accept connections from common H@H server IPs
        # In production, this should check against the actual RPC server IPs from client_login response
        valid_ips = [
            "37.48.81.219", "37.48.81.200", "212.7.200.99", "212.7.202.50", "5.79.104.109",
            "127.0.0.1", "::1"  # Allow localhost for testing
        ]
        return client_ip in valid_ips
    
    def send_status_page(self):
        """Send a simple status page."""
        html = """<!DOCTYPE html>
<html>
<head><title>Hentai@Home Client</title></head>
<body>
<h1>Hentai@Home Python Client</h1>
<p>This is a Hentai@Home client node.</p>
<p>For more information, visit <a href="https://e-hentai.org/">E-Hentai</a>.</p>
</body>
</html>"""
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(html)))
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))
    
    def guess_content_type(self, filename: str) -> str:
        """Guess content type from filename."""
        extension = filename.lower().split('.')[-1] if '.' in filename else ''
        
        content_types = {
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'webp': 'image/webp',
            'bmp': 'image/bmp'
        }
        
        return content_types.get(extension, 'application/octet-stream')
    
    def log_message(self, format, *args):
        """Override log message to use our logging system."""
        Out.debug(f"{self.address_string()} - {format % args}")


class ThreadedHTTPServer(ThreadingMixIn, BaseHTTPServer):
    """Threaded HTTP server."""
    daemon_threads = True
    allow_reuse_address = True


class HTTPServer:
    """HTTP server for the Hentai@Home client."""
    
    def __init__(self, client):
        """Initialize the HTTP server."""
        self.client = client
        self.server = None
        self.server_thread = None
        self.is_running = False
        self.allow_connections = False
        self.is_terminated = False
        
        # Connection tracking
        self.sessions: List = []
        self.session_count = 0
        
        # Flood control
        self.flood_control_table: Dict[str, float] = {}
    
    def start_connection_listener(self, port: int) -> bool:
        """Start the HTTPS server on the specified port."""
        try:
            Out.debug(f"Attempting to start HTTP server on port: {port}")
            
            # Create server
            self.server = ThreadedHTTPServer(('', port), HTTPRequestHandler)
            
            # Configure SSL/TLS
            if not self._configure_ssl():
                Out.error("Failed to configure SSL - falling back to HTTP")
                # Continue without SSL for now, but this should ideally fail
            
            # Start server thread
            self.server_thread = threading.Thread(target=self._run_server)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            self.is_running = True
            protocol = "HTTPS" if hasattr(self.server, 'socket') and hasattr(self.server.socket, 'context') else "HTTP"
            Out.info(f"{protocol} server started on port {port}")
            return True
            
        except Exception as e:
            Out.error(f"Failed to start HTTP server: {e}")
            return False
    
    def _configure_ssl(self) -> bool:
        """Configure SSL/TLS for the server."""
        try:
            # Get server handler to check/download certificate
            client = Settings.get_active_client()
            if not client:
                Out.error("No active client available for SSL configuration")
                return False
            
            server_handler = client.get_server_handler()
            if not server_handler:
                Out.error("No server handler available for SSL configuration")
                return False
            
            # Check if certificate is valid, download if needed
            if not server_handler.is_certificate_valid():
                Out.info("SSL certificate invalid or missing, downloading from server...")
                if not server_handler.download_certificate():
                    Out.error("Failed to download SSL certificate")
                    return False
            
            # Get certificate paths
            p12_path, _ = server_handler.get_certificate_paths()
            
            # Create SSL context
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            
            # Load PKCS#12 certificate directly
            try:
                if Path(p12_path).exists():
                    from cryptography.hazmat.primitives.serialization import pkcs12
                    from cryptography.hazmat.primitives import serialization
                    import tempfile
                    
                    # Read PKCS#12 data
                    with open(p12_path, 'rb') as f:
                        p12_data = f.read()
                    
                    # Try loading with different passwords - client key is the primary password
                    passwords_to_try = [
                        Settings.get_client_key().encode(),  # Most likely - client key
                        None, 
                        b'', 
                        str(Settings.get_client_id()).encode(),
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
                    import os
                    try:
                        os.unlink(temp_cert_path)
                        os.unlink(temp_key_path)
                    except:
                        pass  # Ignore cleanup errors
                    
                    Out.debug("Loaded PKCS#12 certificate for SSL")
                else:
                    raise FileNotFoundError("PKCS#12 certificate file not found")
                    
            except Exception as e:
                Out.error(f"Failed to configure SSL: {e}")
                return False
            
            # Configure SSL settings for H@H
            ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            
            # Apply SSL context to server socket
            self.server.socket = ssl_context.wrap_socket(self.server.socket, server_side=True)
            
            Out.info("SSL/TLS configured successfully")
            return True
            
        except Exception as e:
            Out.error(f"Failed to configure SSL: {e}")
            return False
    
    def _run_server(self):
        """Run the HTTP server."""
        try:
            self.server.serve_forever()
        except Exception as e:
            if not self.client.is_shutting_down():
                Out.error(f"HTTP server error: {e}")
        finally:
            self.is_terminated = True
    
    def stop_connection_listener(self, restart: bool = False):
        """Stop the HTTP server."""
        if self.server:
            Out.info("Stopping HTTP server...")
            self.server.shutdown()
            self.server.server_close()
            self.is_running = False
    
    def allow_normal_connections(self):
        """Allow normal connections to the server."""
        self.allow_connections = True
        Out.info("HTTP server is now accepting connections")
    
    def nuke_old_connections(self):
        """Clean up old connections (placeholder)."""
        # In a real implementation, this would clean up stale connections
        pass
    
    def prune_flood_control_table(self):
        """Prune old entries from flood control table."""
        current_time = time.time()
        cutoff_time = current_time - 300  # 5 minutes
        
        # Remove old entries
        keys_to_remove = [
            ip for ip, timestamp in self.flood_control_table.items()
            if timestamp < cutoff_time
        ]
        
        for ip in keys_to_remove:
            del self.flood_control_table[ip]
    
    def is_cert_expired(self) -> bool:
        """Check if SSL certificate is expired."""
        try:
            client = Settings.get_active_client()
            if not client:
                return True
            
            server_handler = client.get_server_handler()
            if not server_handler:
                return True
                
            return not server_handler.is_certificate_valid()
        except Exception:
            return True
    
    def is_thread_terminated(self) -> bool:
        """Check if the server thread has terminated."""
        return self.is_terminated
    
    def get_hentai_at_home_client(self):
        """Get the client instance."""
        return self.client
