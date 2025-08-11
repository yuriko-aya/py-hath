"""
Multi-threaded streaming proxy file downloader.

This module provides streaming file downloads that can serve data to clients
while simultaneously downloading from upstream servers, similar to the Java
ProxyFileDownloader implementation.
"""

import threading
import time
import hashlib
import tempfile
from pathlib import Path
from typing import Optional, List, Callable, BinaryIO
from urllib.parse import urlparse
import requests
from io import BytesIO

from .out import Out
from .settings import Settings
from .stats import Stats
from .tools import Tools
from .http_bandwidth_monitor import HTTPBandwidthMonitor


class ProxyFileDownloader:
    """
    Multi-threaded streaming proxy file downloader.
    
    Downloads files from upstream servers while simultaneously serving
    data to clients. This allows for efficient proxy serving without
    requiring the entire file to be downloaded first.
    """
    
    def __init__(self, file_id: str, sources: List[str], expected_size: int, expected_hash: str):
        """Initialize the proxy file downloader.
        
        Args:
            file_id: The file identifier
            sources: List of source URLs to try
            expected_size: Expected file size in bytes
            expected_hash: Expected SHA1 hash
        """
        self.file_id = file_id
        self.sources = sources
        self.expected_size = expected_size
        self.expected_hash = expected_hash
        
        # Threading and synchronization
        self.download_lock = threading.Lock()
        self.download_thread: Optional[threading.Thread] = None
        
        # Download state
        self.download_started = False
        self.download_complete = False
        self.download_success = False
        self.proxy_complete = False
        self.file_finalized = False
        
        # Buffer management
        self.buffer_size = 65536  # 64KB buffer like Java version
        self.buffer_threshold = int(self.buffer_size * 0.75)  # 75% threshold
        self.temp_file: Optional[BinaryIO] = None
        self.temp_file_path: Optional[Path] = None
        
        # Tracking
        self.read_offset = 0
        self.write_offset = 0
        self.content_length = 0
        self.content_type = 'application/octet-stream'
        
        # Hash calculation
        self.sha1_digest = hashlib.sha1()
        
        # Bandwidth monitoring
        self.bandwidth_monitor = HTTPBandwidthMonitor.get_instance()
        
    def initialize(self) -> int:
        """Initialize the proxy download.
        
        Returns:
            HTTP status code (200 for success, error codes for failure)
        """
        Out.debug(f"ProxyFileDownloader::initialize with file_id={self.file_id} sources={self.sources}")
        
        for source_url in self.sources:
            try:
                Out.debug(f"ProxyFileDownloader: Requesting file download from {source_url}")
                
                # Get connection info without downloading yet
                response = requests.head(
                    source_url,
                    timeout=5,
                    headers={
                        'Hath-Request': f"{Settings.getClientID()}-{Tools.getSHA1String(Settings.getClientKey() + self.file_id)}",
                        'User-Agent': f"Hentai@Home {Settings.CLIENT_VERSION}"
                    },
                    proxies=self._get_proxy_config()
                )
                
                if response.status_code != 200:
                    Out.warning(f"HEAD request failed with status {response.status_code}")
                    continue
                
                # Check content length
                content_length = response.headers.get('content-length')
                if not content_length:
                    Out.warning("Request host did not send Content-Length, aborting transfer")
                    continue
                
                self.content_length = int(content_length)
                
                if self.content_length > Settings.getMaxAllowedFileSize():
                    Out.warning(f"Reported contentLength {self.content_length} exceeds max allowed filesize {Settings.getMaxAllowedFileSize()}")
                    continue
                
                if self.expected_size and self.content_length != self.expected_size:
                    Out.warning(f"Reported contentLength {self.content_length} does not match expected length {self.expected_size}")
                    continue
                
                # Get content type
                self.content_type = response.headers.get('content-type', 'application/octet-stream')
                
                # Create temporary file
                self.temp_file = tempfile.NamedTemporaryFile(
                    prefix=f"proxyfile_{self.file_id}_",
                    dir=Settings.getTempDir(),
                    delete=False
                )
                self.temp_file_path = Path(self.temp_file.name)
                
                # Start download thread
                self.download_thread = threading.Thread(
                    target=self._download_worker,
                    args=(source_url,),
                    daemon=True
                )
                self.download_thread.start()
                
                return 200
                
            except Exception as e:
                Out.warning(f"Failed to initialize download from {source_url}: {e}")
                self._cleanup()
                continue
        
        return 502  # Bad Gateway
    
    def _get_proxy_config(self) -> Optional[dict]:
        """Get proxy configuration if available."""
        proxy = Settings.getImageProxy()
        if proxy:
            return {'http': str(proxy), 'https': str(proxy)}
        return None
    
    def _download_worker(self, source_url: str):
        """Worker thread that downloads the file."""
        with self.download_lock:
            self.download_started = True
            
        retries = 3
        while retries > 0 and not self.download_success:
            try:
                self._attempt_download(source_url)
                if self.download_success:
                    break
            except Exception as e:
                Out.debug(f"Download attempt failed: {e}")
                retries -= 1
                if retries > 0:
                    time.sleep(1)  # Wait before retry
                    # Reset state for retry
                    self.write_offset = 0
                    self.read_offset = 0
                    self.sha1_digest = hashlib.sha1()
                    if self.temp_file:
                        self.temp_file.seek(0)
                        self.temp_file.truncate()
        
        with self.download_lock:
            self.download_complete = True
            self._check_finalize_file()
    
    def _attempt_download(self, source_url: str):
        """Attempt to download the file from the given URL."""
        response = requests.get(
            source_url,
            timeout=30,
            stream=True,
            headers={
                'Hath-Request': f"{Settings.getClientID()}-{Tools.getSHA1String(Settings.getClientKey() + self.file_id)}",
                'User-Agent': f"Hentai@Home {Settings.CLIENT_VERSION}"
            },
            proxies=self._get_proxy_config()
        )
        
        response.raise_for_status()
        
        download_start = time.time()
        buffer = bytearray()
        
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                break
            
            # Check timeout
            if time.time() - download_start > 300:  # 5 minute timeout
                raise TimeoutError("Download time limit exceeded")
            
            # Add to buffer
            buffer.extend(chunk)
            self.read_offset += len(chunk)
            
            # Apply bandwidth throttling
            self.bandwidth_monitor.throttle_bandwidth(len(chunk))
            
            # Flush buffer when threshold is reached or download is complete
            should_flush = (
                len(buffer) >= self.buffer_threshold or
                self.read_offset >= self.content_length or
                (self.content_length > 0 and self.read_offset >= self.content_length)
            )
            
            if should_flush and buffer:
                self._flush_buffer(buffer)
                buffer.clear()
        
        # Final flush
        if buffer:
            self._flush_buffer(buffer)
        
        if self.write_offset != self.content_length:
            raise ValueError(f"Download incomplete: {self.write_offset}/{self.content_length} bytes")
        
        Stats.fileRcvd()
        self.download_success = True
    
    def _flush_buffer(self, buffer: bytearray):
        """Flush buffer to temporary file and update hash."""
        if not buffer:
            return
        
        # Write to file
        self.temp_file.write(buffer)
        self.temp_file.flush()
        
        # Update hash
        self.sha1_digest.update(buffer)
        
        # Update stats
        bytes_written = len(buffer)
        self.write_offset += bytes_written
        Stats.bytesRcvd(bytes_written)
        
        Out.debug(f"Wrote {bytes_written} bytes to temp file (total: {self.write_offset}/{self.content_length})")
    
    def get_content_type(self) -> str:
        """Get the content type of the file."""
        return self.content_type
    
    def get_content_length(self) -> int:
        """Get the content length of the file."""
        return self.content_length
    
    def get_current_write_offset(self) -> int:
        """Get the current write offset (bytes downloaded)."""
        return self.write_offset
    
    def fill_buffer(self, buffer: bytearray, offset: int) -> int:
        """Fill the provided buffer with data from the temporary file.
        
        Args:
            buffer: Buffer to fill
            offset: Byte offset to read from
            
        Returns:
            Number of bytes read
        """
        if not self.temp_file:
            return 0
        
        max_read = len(buffer)
        bytes_available = self.write_offset - offset
        
        if bytes_available <= 0:
            return 0
        
        bytes_to_read = min(max_read, bytes_available)
        
        # Read from temporary file
        self.temp_file.seek(offset)
        data = self.temp_file.read(bytes_to_read)
        
        # Copy to buffer
        buffer[:len(data)] = data
        
        return len(data)
    
    def read_range(self, start: int, end: int) -> bytes:
        """Read a range of bytes from the downloaded file.
        
        Args:
            start: Start byte position
            end: End byte position (inclusive)
            
        Returns:
            Bytes in the specified range
        """
        if not self.temp_file:
            return b''
        
        # Wait for sufficient data to be available
        while self.write_offset <= end and not self.download_complete:
            time.sleep(0.01)  # Small delay to prevent busy waiting
        
        if self.write_offset <= start:
            return b''
        
        # Clamp end to available data
        actual_end = min(end, self.write_offset - 1)
        
        if actual_end < start:
            return b''
        
        # Read the range
        self.temp_file.seek(start)
        return self.temp_file.read(actual_end - start + 1)
    
    def wait_for_bytes(self, byte_position: int, timeout: float = 30.0) -> bool:
        """Wait for a specific byte position to be available.
        
        Args:
            byte_position: Position to wait for
            timeout: Maximum time to wait in seconds
            
        Returns:
            True if bytes are available, False on timeout
        """
        start_time = time.time()
        
        while self.write_offset <= byte_position and not self.download_complete:
            if time.time() - start_time > timeout:
                return False
            time.sleep(0.01)
        
        return self.write_offset > byte_position or self.download_complete
    
    def proxy_thread_completed(self):
        """Called when the proxy serving thread completes."""
        Stats.fileSent()
        with self.download_lock:
            self.proxy_complete = True
            self._check_finalize_file()
    
    def _check_finalize_file(self):
        """Check if file can be finalized and import to cache."""
        if not self.download_complete or not self.proxy_complete:
            return
        
        if self.file_finalized:
            Out.warning("ProxyFileDownloader: Attempted to finalize file that was already finalized")
            return
        
        self.file_finalized = True
        
        try:
            if self.temp_file:
                self.temp_file.close()
            
            if not self.temp_file_path or not self.temp_file_path.exists():
                Out.debug(f"Proxy-downloaded file {self.file_id} temp file missing")
                return
            
            if self.temp_file_path.stat().st_size != self.content_length:
                Out.debug(f"Proxy-downloaded file {self.file_id} is incomplete, and will not be stored. (bytes={self.temp_file_path.stat().st_size})")
            else:
                # Verify hash
                sha1_hash = self.sha1_digest.hexdigest()
                
                if self.expected_hash and self.expected_hash != sha1_hash:
                    Out.debug(f"Proxy-downloaded file {self.file_id} is corrupt, and will not be stored. (digest={sha1_hash})")
                else:
                    # Import to cache if we have access to the client
                    client = Settings.get_active_client()
                    if client and client.get_cache_handler():
                        # Create HVFile for import
                        from .cache_handler import HVFile
                        hv_file = HVFile.getHVFileFromFileid(self.file_id)
                        
                        if hv_file and client.get_cache_handler().import_file_to_cache(self.temp_file_path, hv_file):
                            Out.debug(f"Proxy-downloaded file {self.file_id} was successfully stored in cache.")
                        else:
                            Out.debug(f"Proxy-downloaded file {self.file_id} exists or could not be imported to the cache.")
            
        finally:
            self._cleanup()
    
    def _cleanup(self):
        """Clean up temporary resources."""
        try:
            if self.temp_file:
                self.temp_file.close()
        except:
            pass
        
        try:
            if self.temp_file_path and self.temp_file_path.exists():
                self.temp_file_path.unlink()
        except:
            pass
    
    def __del__(self):
        """Ensure cleanup on destruction."""
        self._cleanup()
