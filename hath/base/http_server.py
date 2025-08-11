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
from .http_session import HTTPSession, HTTPSessionManager
from .http_bandwidth_monitor import HTTPBandwidthMonitor
from .file_validator import FileValidator
from .stats import Stats


class HTTPRequestHandler(BaseHTTPRequestHandler):
    """Custom HTTP request handler for Hentai@Home."""
    
    # Override the default server signature
    server_version = f"Genetic Lifeform and Distributed Open Server/{Settings.CLIENT_VERSION}"
    
    def __init__(self, *args, **kwargs):
        self.hath_server = None
        self.session = None
        self.bandwidth_monitor = HTTPBandwidthMonitor.get_instance()
        super().__init__(*args, **kwargs)
    
    def setup(self):
        """Set up the request handler with session tracking."""
        super().setup()
        
        # Create HTTP session for this connection
        client_ip = self.client_address[0]
        client_port = self.client_address[1]
        self.session = HTTPSessionManager.get_instance().create_session(client_ip, client_port)
        
        if self.session:
            Out.debug(f"Created session {self.session.session_id} for {client_ip}:{client_port}")
        else:
            Out.warning(f"Failed to create session for {client_ip}:{client_port} - connection limit reached")
    
    def finish(self):
        """Clean up the request handler and session."""
        if self.session:
            HTTPSessionManager.get_instance().end_session(self.session.session_id)
            Out.debug(f"Ended session {self.session.session_id}")
        super().finish()
    
    def do_GET(self):
        """Handle GET requests."""
        try:
            # Update session and stats
            if self.session:
                self.session.start_processing_request("GET " + self.path)
            
            Stats.get_instance().increment_files_received()
            
            self.handle_request()
            
        except (ConnectionResetError, BrokenPipeError):
            # Client disconnected - this is normal, don't log as error
            Out.debug(f"Client {self.client_address[0]} disconnected during GET request")
        except (ssl.SSLError, OSError) as e:
            # SSL/network errors
            if "EOF occurred in violation of protocol" in str(e) or "Connection reset by peer" in str(e):
                Out.debug(f"SSL/network error during GET request from {self.client_address[0]}: {e}")
            else:
                Out.warning(f"SSL/network error handling GET request from {self.client_address[0]}: {e}")
        except Exception as e:
            Out.error(f"Error handling GET request from {self.client_address[0]}: {e}")
            try:
                self.send_error(500, "Internal Server Error")
            except:
                pass  # Connection might already be closed
        finally:
            # End request processing
            if self.session:
                self.session.end_processing_request()
    
    def do_HEAD(self):
        """Handle HEAD requests."""
        try:
            # Update session and stats
            if self.session:
                self.session.start_processing_request("HEAD " + self.path)
            
            Stats.get_instance().increment_files_received()
            
            self.handle_request()
            
        except (ConnectionResetError, BrokenPipeError):
            # Client disconnected - this is normal, don't log as error
            Out.debug(f"Client {self.client_address[0]} disconnected during HEAD request")
        except (ssl.SSLError, OSError) as e:
            # SSL/network errors
            if "EOF occurred in violation of protocol" in str(e) or "Connection reset by peer" in str(e):
                Out.debug(f"SSL/network error during HEAD request from {self.client_address[0]}: {e}")
            else:
                Out.warning(f"SSL/network error handling HEAD request from {self.client_address[0]}: {e}")
        except Exception as e:
            Out.error(f"Error handling HEAD request from {self.client_address[0]}: {e}")
            try:
                self.send_error(500, "Internal Server Error")
            except:
                pass  # Connection might already be closed
        finally:
            # End request processing
            if self.session:
                self.session.end_processing_request()
    
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
        """Serve a file from local cache with advanced HTTP features."""
        try:
            file_path = hv_file.get_local_file_ref()
            
            if not file_path.exists():
                self.send_error(404, "File not found")
                return
            
            # Validate file integrity before serving (if enabled)
            validator = FileValidator.get_instance()
            if Settings.get_bool('validate_files_on_serve', True):
                expected_hash = hv_file.hash  # Assuming the HVFile has the expected hash
                if expected_hash and not validator.validate_file(file_path, expected_hash):
                    Out.warning(f"File validation failed for {hv_file.file_id}, removing from cache")
                    # Mark file as invalid and remove
                    cache_handler = Settings.get_active_client().get_cache_handler()
                    if cache_handler:
                        cache_handler.remove_file_from_cache(hv_file.file_id)
                    self.send_error(404, "File corrupted")
                    return
            
            # Get file stats for conditional headers
            file_stat = file_path.stat()
            file_size = file_stat.st_size
            last_modified = file_stat.st_mtime
            
            # Generate ETag based on file size and modification time
            etag = f'"{file_size}-{int(last_modified)}"'
            
            # Handle conditional requests
            if self.handle_conditional_request(last_modified, etag):
                return  # 304 Not Modified sent
            
            # Determine content type
            content_type = self.guess_content_type(file_path.name, file_path)
            
            # Handle Range requests
            range_header = self.headers.get('Range')
            if range_header and range_header.startswith('bytes='):
                self.serve_range_request(file_path, file_size, content_type, last_modified, etag, range_header)
            else:
                self.serve_full_file(file_path, file_size, content_type, last_modified, etag)
                
        except Exception as e:
            Out.error(f"Error serving file from cache: {e}")
            self.send_error(500, "Internal Server Error")
    
    def handle_conditional_request(self, last_modified: float, etag: str) -> bool:
        """Handle conditional HTTP requests (If-Modified-Since, If-None-Match).
        
        Returns:
            True if 304 Not Modified was sent, False otherwise
        """
        # Handle If-None-Match (ETag)
        if_none_match = self.headers.get('If-None-Match')
        if if_none_match:
            # Simple ETag comparison (should handle weak/strong ETags in production)
            if if_none_match == etag or if_none_match == '*':
                self.send_response(304)
                self.send_header('ETag', etag)
                self.send_header('Cache-Control', 'public, max-age=31536000')
                self.end_headers()
                return True
        
        # Handle If-Modified-Since
        if_modified_since = self.headers.get('If-Modified-Since')
        if if_modified_since:
            try:
                import email.utils
                client_time = email.utils.parsedate_to_datetime(if_modified_since).timestamp()
                # Only compare to second precision (HTTP dates don't include milliseconds)
                if int(last_modified) <= int(client_time):
                    self.send_response(304)
                    self.send_header('Last-Modified', email.utils.formatdate(last_modified, usegmt=True))
                    self.send_header('ETag', etag)
                    self.send_header('Cache-Control', 'public, max-age=31536000')
                    self.end_headers()
                    return True
            except (ValueError, TypeError):
                # Invalid date format, ignore
                pass
        
        return False
    
    def serve_full_file(self, file_path: Path, file_size: int, content_type: str, 
                       last_modified: float, etag: str):
        """Serve a complete file with proper headers."""
        import email.utils
        
        # Send headers
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(file_size))
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Last-Modified', email.utils.formatdate(last_modified, usegmt=True))
        self.send_header('ETag', etag)
        # Tell browser to display inline instead of downloading
        self.send_header('Content-Disposition', 'inline')
        # Cache for one year (31536000 seconds)
        self.send_header('Cache-Control', 'public, max-age=31536000')
        self.end_headers()
        
        # Send file content (only for GET, not HEAD)
        if self.command == 'GET':
            self.send_file_data(file_path, 0, file_size)
    
    def serve_range_request(self, file_path: Path, file_size: int, content_type: str,
                           last_modified: float, etag: str, range_header: str):
        """Serve a partial file response (HTTP 206)."""
        import email.utils
        
        try:
            # Parse range header: "bytes=start-end"
            ranges = self.parse_range_header(range_header, file_size)
            
            if not ranges:
                # Invalid range
                self.send_response(416)  # Range Not Satisfiable
                self.send_header('Content-Range', f'bytes */{file_size}')
                self.send_header('Content-Type', content_type)
                self.end_headers()
                return
            
            if len(ranges) == 1:
                # Single range
                start, end = ranges[0]
                content_length = end - start + 1
                
                self.send_response(206)  # Partial Content
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(content_length))
                self.send_header('Content-Range', f'bytes {start}-{end}/{file_size}')
                self.send_header('Accept-Ranges', 'bytes')
                self.send_header('Last-Modified', email.utils.formatdate(last_modified, usegmt=True))
                self.send_header('ETag', etag)
                self.send_header('Cache-Control', 'public, max-age=31536000')
                self.end_headers()
                
                # Send partial content (only for GET, not HEAD)
                if self.command == 'GET':
                    self.send_file_data(file_path, start, content_length)
            else:
                # Multiple ranges - use multipart/byteranges
                self.serve_multipart_ranges(file_path, file_size, content_type, 
                                          last_modified, etag, ranges)
                
        except Exception as e:
            Out.error(f"Error serving range request: {e}")
            self.send_error(500, "Internal Server Error")
    
    def parse_range_header(self, range_header: str, file_size: int) -> list:
        """Parse HTTP Range header and return list of (start, end) tuples."""
        ranges = []
        
        try:
            # Remove "bytes=" prefix
            range_spec = range_header[6:]  # len("bytes=") = 6
            
            # Split multiple ranges
            for range_item in range_spec.split(','):
                range_item = range_item.strip()
                
                if '-' not in range_item:
                    continue
                
                start_str, end_str = range_item.split('-', 1)
                
                if start_str and end_str:
                    # Both start and end specified: "200-299"
                    start = int(start_str)
                    end = int(end_str)
                elif start_str:
                    # Only start specified: "200-" (from 200 to end)
                    start = int(start_str)
                    end = file_size - 1
                elif end_str:
                    # Only end specified: "-500" (last 500 bytes)
                    suffix_length = int(end_str)
                    start = max(0, file_size - suffix_length)
                    end = file_size - 1
                else:
                    # Invalid range
                    continue
                
                # Validate range
                if start < 0 or end < 0 or start >= file_size or end >= file_size or start > end:
                    continue
                
                ranges.append((start, end))
        
        except (ValueError, IndexError):
            # Invalid range format
            return []
        
        return ranges
    
    def serve_multipart_ranges(self, file_path: Path, file_size: int, content_type: str,
                              last_modified: float, etag: str, ranges: list):
        """Serve multiple ranges as multipart/byteranges."""
        import email.utils
        import uuid
        
        # Generate boundary
        boundary = f"----boundary_{uuid.uuid4().hex}"
        
        # Calculate total content length
        content_length = 0
        for start, end in ranges:
            # Boundary + headers + CRLF + data + CRLF
            range_header = f"Content-Type: {content_type}\r\nContent-Range: bytes {start}-{end}/{file_size}\r\n\r\n"
            content_length += len(f"--{boundary}\r\n") + len(range_header) + (end - start + 1) + len("\r\n")
        content_length += len(f"--{boundary}--\r\n")
        
        # Send headers
        self.send_response(206)  # Partial Content
        self.send_header('Content-Type', f'multipart/byteranges; boundary={boundary}')
        self.send_header('Content-Length', str(content_length))
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Last-Modified', email.utils.formatdate(last_modified, usegmt=True))
        self.send_header('ETag', etag)
        self.send_header('Cache-Control', 'public, max-age=31536000')
        self.end_headers()
        
        # Send multipart content (only for GET, not HEAD)
        if self.command == 'GET':
            with open(file_path, 'rb') as f:
                for start, end in ranges:
                    # Send boundary and headers
                    boundary_data = f"--{boundary}\r\nContent-Type: {content_type}\r\nContent-Range: bytes {start}-{end}/{file_size}\r\n\r\n"
                    self.wfile.write(boundary_data.encode('utf-8'))
                    
                    # Send range data
                    f.seek(start)
                    self.send_file_chunk(f, end - start + 1)
                    
                    # Send CRLF after each part
                    self.wfile.write(b"\r\n")
                
                # Send final boundary
                final_boundary = f"--{boundary}--\r\n"
                self.wfile.write(final_boundary.encode('utf-8'))
    
    def send_file_data(self, file_path: Path, start: int, length: int):
        """Send file data with bandwidth throttling."""
        bytes_sent = 0
        bandwidth_monitor = HTTPBandwidthMonitor.get_instance()
        
        try:
            with open(file_path, 'rb') as f:
                f.seek(start)
                remaining = length
                
                while remaining > 0:
                    # Read chunk (max 8KB)
                    chunk_size = min(8192, remaining)
                    data = f.read(chunk_size)
                    if not data:
                        break
                    
                    # Apply bandwidth throttling
                    if bandwidth_monitor:
                        bandwidth_monitor.throttle_bandwidth(len(data))
                    
                    # Send data
                    self.wfile.write(data)
                    bytes_sent += len(data)
                    remaining -= len(data)
                    
                    # Update stats
                    Stats.get_instance().add_bytes_sent(len(data))
        
        except Exception as e:
            Out.warning(f"Error sending file data: {e}")
        
        Out.debug(f"Sent {bytes_sent} bytes from {file_path}")
    
    def send_file_chunk(self, file_obj, length: int):
        """Send a chunk of data from an open file object."""
        bytes_sent = 0
        bandwidth_monitor = HTTPBandwidthMonitor.get_instance()
        remaining = length
        
        while remaining > 0:
            chunk_size = min(8192, remaining)
            data = file_obj.read(chunk_size)
            if not data:
                break
            
            # Apply bandwidth throttling
            if bandwidth_monitor:
                bandwidth_monitor.throttle_bandwidth(len(data))
            
            # Send data
            self.wfile.write(data)
            bytes_sent += len(data)
            remaining -= len(data)
            
            # Update stats
            Stats.get_instance().add_bytes_sent(len(data))
            
        # Mark as successfully sent and recently accessed
        Stats.get_instance().increment_files_sent()
        cache_handler = Settings.get_active_client().get_cache_handler()
        if cache_handler:
            cache_handler.mark_recently_accessed(hv_file)
    
    def serve_file_via_proxy(self, fileindex: str, xres: str, file_id: str):
        """Serve a file by proxying from the server using streaming download."""
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
            
            # Get file info for validation
            from .cache_handler import HVFile
            hv_file = HVFile.getHVFileFromFileid(file_id)
            
            if not hv_file:
                self.send_error(404, "File info not available")
                return
            
            # Use streaming proxy downloader
            from .proxy_file_downloader import ProxyFileDownloader
            
            proxy_downloader = ProxyFileDownloader(
                file_id=file_id,
                sources=sources,
                expected_size=hv_file.getSize(),
                expected_hash=hv_file.getHash()
            )
            
            # Initialize the download
            status_code = proxy_downloader.initialize()
            
            if status_code != 200:
                Out.warning(f"Failed to initialize proxy download for file {file_id}")
                self.send_error(status_code, "Failed to initialize proxy download")
                return
            
            # Check if this is a Range request
            range_header = self.headers.get('Range')
            if range_header:
                self._serve_proxy_range_request(proxy_downloader, hv_file, range_header)
            else:
                self._serve_proxy_full_file(proxy_downloader, hv_file)
                
        except Exception as e:
            Out.warning(f"Error serving proxy file {file_id}: {e}")
            self.send_error(500, "Internal server error")
    
    def _serve_proxy_full_file(self, proxy_downloader, hv_file):
        """Serve the full proxy file with streaming."""
        try:
            # Send response headers
            self.send_response(200)
            self.send_header('Content-Type', proxy_downloader.get_content_type())
            self.send_header('Content-Length', str(proxy_downloader.get_content_length()))
            self.send_header('Accept-Ranges', 'bytes')
            
            # Add caching headers
            last_modified = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())
            self.send_header('Last-Modified', last_modified)
            
            # Generate ETag from file info
            etag = f'"{hv_file.getHash()[:16]}"'
            self.send_header('ETag', etag)
            self.send_header('Cache-Control', 'public, max-age=86400')
            
            self.end_headers()
            
            # Stream the file data
            self._stream_proxy_data(proxy_downloader, 0, proxy_downloader.get_content_length() - 1)
            
        except Exception as e:
            Out.warning(f"Error serving full proxy file: {e}")
            raise
        finally:
            proxy_downloader.proxy_thread_completed()
    
    def _serve_proxy_range_request(self, proxy_downloader, hv_file, range_header: str):
        """Serve a range request for a proxy file."""
        try:
            file_size = proxy_downloader.get_content_length()
            ranges = self._parse_range_header(range_header, file_size)
            
            if not ranges:
                # Invalid range
                self.send_response(416)  # Range Not Satisfiable
                self.send_header('Content-Range', f'bytes */{file_size}')
                self.end_headers()
                return
            
            if len(ranges) == 1:
                # Single range
                start, end = ranges[0]
                content_length = end - start + 1
                
                self.send_response(206)  # Partial Content
                self.send_header('Content-Type', proxy_downloader.get_content_type())
                self.send_header('Content-Length', str(content_length))
                self.send_header('Content-Range', f'bytes {start}-{end}/{file_size}')
                self.send_header('Accept-Ranges', 'bytes')
                
                # Add caching headers
                last_modified = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())
                self.send_header('Last-Modified', last_modified)
                
                etag = f'"{hv_file.getHash()[:16]}"'
                self.send_header('ETag', etag)
                
                self.end_headers()
                
                # Stream the range
                self._stream_proxy_data(proxy_downloader, start, end)
                
            else:
                # Multiple ranges - use multipart response
                boundary = f"boundary{time.time()}"
                
                self.send_response(206)
                self.send_header('Content-Type', f'multipart/byteranges; boundary={boundary}')
                
                # Calculate total content length for multipart response
                total_length = 0
                for start, end in ranges:
                    part_length = end - start + 1
                    part_header = (
                        f"\r\n--{boundary}\r\n"
                        f"Content-Type: {proxy_downloader.get_content_type()}\r\n"
                        f"Content-Range: bytes {start}-{end}/{file_size}\r\n\r\n"
                    )
                    total_length += len(part_header.encode()) + part_length
                
                # Add final boundary
                total_length += len(f"\r\n--{boundary}--\r\n".encode())
                
                self.send_header('Content-Length', str(total_length))
                self.end_headers()
                
                # Send multipart data
                for start, end in ranges:
                    part_header = (
                        f"\r\n--{boundary}\r\n"
                        f"Content-Type: {proxy_downloader.get_content_type()}\r\n"
                        f"Content-Range: bytes {start}-{end}/{file_size}\r\n\r\n"
                    )
                    self.wfile.write(part_header.encode())
                    self._stream_proxy_data(proxy_downloader, start, end)
                
                # Send final boundary
                self.wfile.write(f"\r\n--{boundary}--\r\n".encode())
                
        except Exception as e:
            Out.warning(f"Error serving proxy range request: {e}")
            raise
        finally:
            proxy_downloader.proxy_thread_completed()
    
    def _stream_proxy_data(self, proxy_downloader, start_byte: int, end_byte: int):
        """Stream data from proxy downloader to client."""
        chunk_size = 8192
        current_pos = start_byte
        
        while current_pos <= end_byte:
            # Calculate chunk size for this iteration
            remaining = end_byte - current_pos + 1
            read_size = min(chunk_size, remaining)
            
            # Wait for data to be available
            if not proxy_downloader.wait_for_bytes(current_pos + read_size - 1, timeout=30.0):
                Out.warning(f"Timeout waiting for proxy data at position {current_pos}")
                break
            
            # Read data from proxy downloader
            data = proxy_downloader.read_range(current_pos, current_pos + read_size - 1)
            
            if not data:
                Out.warning(f"No data available from proxy downloader at position {current_pos}")
                break
            
            # Apply bandwidth throttling
            self.bandwidth_monitor.throttle_bandwidth(len(data))
            
            # Send data to client
            try:
                self.wfile.write(data)
                self.wfile.flush()
                current_pos += len(data)
                
                # Update stats
                Stats.bytesSent(len(data))
                
            except BrokenPipeError:
                Out.debug("Client disconnected during proxy streaming")
                break
            except Exception as e:
                Out.warning(f"Error writing proxy data to client: {e}")
                break
                
        except Exception as e:
            Out.warning(f"Error serving proxy file {file_id}: {e}")
            self.send_error(500, "Internal server error")
    
    
    def send_data_with_throttling(self, data: bytes):
        """Send data with bandwidth throttling and stats tracking."""
        bytes_sent = 0
        bandwidth_monitor = HTTPBandwidthMonitor.get_instance()
        
        try:
            # Send data in chunks with bandwidth throttling
            chunk_size = 8192
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                
                # Apply bandwidth throttling
                if bandwidth_monitor:
                    bandwidth_monitor.throttle_bandwidth(len(chunk))
                
                # Send chunk
                self.wfile.write(chunk)
                bytes_sent += len(chunk)
                
                # Update stats
                Stats.get_instance().add_bytes_sent(len(chunk))
                
        except (ConnectionResetError, BrokenPipeError):
            # Client disconnected - this is normal, don't log as error
            Out.debug(f"Client disconnected during data transfer")
        except (ssl.SSLError, OSError) as e:
            # SSL/network errors during file transfer
            if "EOF occurred in violation of protocol" in str(e) or "Connection reset by peer" in str(e):
                Out.debug(f"SSL/network error during transfer (client likely disconnected): {e}")
            else:
                Out.warning(f"SSL/network error during transfer: {e}")
        
        Out.debug(f"Sent {bytes_sent} bytes with throttling")
    
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
                # Implement a basic proxy connectivity test
                successful_tests = 0
                total_time_millis = 0
                
                try:
                    # Check if proxy is configured
                    proxy_host = Settings.get_image_proxy_host()
                    proxy_port = Settings.get_image_proxy_port()
                    proxy_type = Settings.get_image_proxy_type()
                    
                    if proxy_host and proxy_type:
                        import time
                        import requests
                        
                        start_time = time.time()
                        
                        # Test proxy connectivity with a simple request
                        proxy_url = f"{proxy_type}://{proxy_host}:{proxy_port}"
                        proxies = {'http': proxy_url, 'https': proxy_url}
                        
                        # Test with a reliable endpoint (Google DNS over HTTPS)
                        test_url = "https://dns.google/resolve?name=google.com&type=A"
                        
                        try:
                            response = requests.get(test_url, proxies=proxies, timeout=10)
                            if response.status_code == 200:
                                successful_tests = 1
                            
                        except Exception as e:
                            Out.debug(f"Proxy test failed: {e}")
                        
                        end_time = time.time()
                        total_time_millis = int((end_time - start_time) * 1000)
                        
                        Out.info(f"Proxy test completed: {successful_tests} successful, {total_time_millis}ms")
                    else:
                        Out.info("No proxy configured, skipping proxy test")
                        
                except Exception as e:
                    Out.warning(f"Proxy test error: {e}")
                
                # Format response like Java: OK:successfulTests-totalTimeMillis
                response_text = f"OK:{successful_tests}-{total_time_millis}"
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(response_text.encode('utf-8'))
                Out.debug(f"Responded to server threaded_proxy_test command: {response_text}")
                
            elif command == 'start_downloader':
                # Java: client.startDownloader();
                # Java: return new HTTPResponseProcessorText("");
                client = Settings.get_active_client()
                if client:
                    try:
                        # Start gallery downloader if not already running
                        if not hasattr(client, 'gallery_downloader') or client.gallery_downloader is None:
                            if Settings.get_bool('enable_gallery_downloader', True):
                                Out.info("Starting gallery downloader via server command...")
                                from ..gallery_downloader import GalleryDownloader
                                client.gallery_downloader = GalleryDownloader(client)
                                Out.info("Gallery downloader started successfully")
                            else:
                                Out.info("Gallery downloader is disabled in settings")
                        else:
                            Out.info("Gallery downloader is already running")
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
                        # Request certificate refresh from server
                        Out.info("Certificate refresh requested via server command...")
                        client.do_cert_refresh = True
                        
                        # Also try to refresh immediately if server handler is available
                        server_handler = client.get_server_handler()
                        if server_handler:
                            # Trigger certificate download from server
                            if server_handler.download_client_certificate():
                                Out.info("Client certificate refreshed successfully")
                            else:
                                Out.warning("Failed to refresh client certificate")
                        else:
                            Out.info("Certificate refresh scheduled for next server communication")
                            
                    except Exception as e:
                        Out.warning(f"Failed to refresh certificates: {e}")
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'')
                Out.debug("Responded to server refresh_certs command")
                
            elif command == 'stop_downloader':
                # Stop gallery downloader
                client = Settings.get_active_client()
                if client:
                    try:
                        if hasattr(client, 'gallery_downloader') and client.gallery_downloader:
                            Out.info("Stopping gallery downloader via server command...")
                            client.gallery_downloader.shutdown()
                            client.gallery_downloader = None
                            Out.info("Gallery downloader stopped successfully")
                        else:
                            Out.info("Gallery downloader is not running")
                    except Exception as e:
                        Out.warning(f"Failed to stop downloader: {e}")
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'')
                Out.debug("Responded to server stop_downloader command")
                
            elif command == 'status':
                # Return client status information
                client = Settings.get_active_client()
                status_info = []
                
                if client:
                    try:
                        # Basic client information
                        status_info.append(f"Client ID: {Settings.get_client_id()}")
                        status_info.append(f"Client Version: {Settings.CLIENT_VERSION}")
                        status_info.append(f"Running: {not client.is_shutting_down()}")
                        status_info.append(f"Suspended: {client.is_suspended()}")
                        
                        # Gallery downloader status
                        if hasattr(client, 'gallery_downloader') and client.gallery_downloader:
                            status_info.append("Gallery Downloader: Running")
                        else:
                            status_info.append("Gallery Downloader: Stopped")
                        
                        # HTTP server status
                        if client.http_server:
                            status_info.append(f"HTTP Server: Running on port {Settings.get_client_port()}")
                        else:
                            status_info.append("HTTP Server: Stopped")
                        
                        # Proxy configuration
                        proxy_host = Settings.get_image_proxy_host()
                        if proxy_host:
                            status_info.append(f"Proxy: {Settings.get_image_proxy_type()}://{proxy_host}:{Settings.get_image_proxy_port()}")
                        else:
                            status_info.append("Proxy: Not configured")
                        
                    except Exception as e:
                        status_info.append(f"Error getting status: {e}")
                else:
                    status_info.append("Client: Not running")
                
                status_text = '\n'.join(status_info)
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(status_text.encode('utf-8'))
                Out.debug("Responded to server status command")
                
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
    
    def guess_content_type(self, filename: str, file_path: Optional[Path] = None) -> str:
        """Guess content type from filename or file magic bytes."""
        # First try by extension
        extension = filename.lower().split('.')[-1] if '.' in filename else ''
        
        content_types = {
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'webp': 'image/webp',
            'bmp': 'image/bmp',
            'webm': 'video/webm',
            'mp4': 'video/mp4'
        }
        
        if extension in content_types:
            return content_types[extension]
        
        # If no extension, try to detect from file magic bytes (for cached H@H files)
        if file_path and file_path.exists():
            try:
                with open(file_path, 'rb') as f:
                    magic = f.read(16)  # Read first 16 bytes
                
                # Common image file signatures
                if magic.startswith(b'\xFF\xD8\xFF'):  # JPEG
                    return 'image/jpeg'
                elif magic.startswith(b'\x89\x50\x4E\x47'):  # PNG
                    return 'image/png'
                elif magic.startswith(b'\x47\x49\x46\x38'):  # GIF
                    return 'image/gif'
                elif magic.startswith(b'RIFF') and b'WEBP' in magic:  # WebP
                    return 'image/webp'
                elif magic.startswith(b'\x42\x4D'):  # BMP
                    return 'image/bmp'
                elif magic.startswith(b'\x1A\x45\xDF\xA3'):  # WebM
                    return 'video/webm'
                elif magic.startswith(b'\x00\x00\x00\x20\x66\x74\x79\x70'):  # MP4
                    return 'video/mp4'
            except Exception:
                pass  # Fall through to default
        
        # Default - for H@H files, assume JPEG if we can't determine
        return 'image/jpeg'
    
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
        
        # Connection tracking (legacy - now using HTTPSessionManager)
        self.sessions: List = []
        self.session_count = 0
        
        # Initialize session manager and bandwidth monitor
        self.session_manager = HTTPSessionManager.get_instance()
        self.bandwidth_monitor = HTTPBandwidthMonitor.get_instance()
        self.stats = Stats.get_instance()
        
        # Configure session manager with max connections from settings
        max_connections = Settings.get_int('max_connections', 100)
        max_connections_per_ip = Settings.get_int('max_connections_per_ip', 10)
        self.session_manager.set_connection_limits(max_connections, max_connections_per_ip)
        
        # Flood control
        self.flood_control_table: Dict[str, float] = {}
        
        Out.debug(f"HTTP server initialized with max {max_connections} connections ({max_connections_per_ip} per IP)")
    
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
            
            # Shutdown session manager and close all active sessions
            self.session_manager.shutdown()
            
            self.server.shutdown()
            self.server.server_close()
            self.is_running = False
            
            Out.info("HTTP server stopped")
    
    def allow_normal_connections(self):
        """Allow normal connections to the server."""
        self.allow_connections = True
        Out.info("HTTP server is now accepting connections")
    
    def nuke_old_connections(self):
        """Clean up old connections."""
        # Use our session manager to clean up old sessions
        cleaned_count = self.session_manager.cleanup_expired_sessions()
        if cleaned_count > 0:
            Out.debug(f"Cleaned up {cleaned_count} expired sessions")
    
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
