"""
File downloader for fetching files from E-Hentai servers.

This module provides robust file downloading with retry logic,
bandwidth limiting, progress tracking, and multiple download modes.
"""

import threading
import time
import requests
from pathlib import Path
from typing import Optional, Callable, Union
from urllib.parse import urlparse
import hashlib

from .out import Out
from .settings import Settings
from .http_bandwidth_monitor import HTTPBandwidthMonitor


class FileDownloader:
    """Downloads files from URLs with various options and retry logic."""
    
    def __init__(self, source_url: str, timeout: int = 30000, max_download_time: int = 300000, 
                 output_path: Optional[Path] = None, allow_proxy: bool = False):
        """Initialize the file downloader.
        
        Args:
            source_url: URL to download from
            timeout: Connection timeout in milliseconds
            max_download_time: Maximum download time in milliseconds
            output_path: Path to save file to (if None, stores in memory)
            allow_proxy: Whether to allow proxy usage
        """
        self.source_url = source_url
        self.timeout = timeout / 1000.0  # Convert to seconds
        self.max_download_time = max_download_time / 1000.0  # Convert to seconds
        self.output_path = output_path
        self.allow_proxy = allow_proxy
        self.retries = 3
        
        # Download state
        self.started = False
        self.successful = False
        self.discard_data = False
        self.content_length = 0
        self.download_data: Optional[bytes] = None
        
        # Timing information
        self.time_download_start = 0
        self.time_first_byte = 0
        self.time_download_finish = 0
        
        # Threading
        self.download_thread: Optional[threading.Thread] = None
        self.download_lock = threading.Lock()
        
        # Bandwidth limiting
        self.download_limiter: Optional[HTTPBandwidthMonitor] = None
        
        # Progress callback
        self.progress_callback: Optional[Callable[[int, int], None]] = None
    
    def set_download_limiter(self, limiter: HTTPBandwidthMonitor):
        """Set bandwidth limiter for this download.
        
        Args:
            limiter: The bandwidth monitor to use
        """
        self.download_limiter = limiter
    
    def set_progress_callback(self, callback: Callable[[int, int], None]):
        """Set progress callback function.
        
        Args:
            callback: Function called with (bytes_downloaded, total_bytes)
        """
        self.progress_callback = callback
    
    def set_discard_data(self, discard: bool):
        """Set whether to discard downloaded data (for speed tests).
        
        Args:
            discard: True to discard data, False to keep it
        """
        self.discard_data = discard
    
    def download_file(self) -> bool:
        """Download the file synchronously.
        
        Returns:
            True if download was successful
        """
        if self.download_thread is None:
            # Direct download without threading
            self._run_download()
        else:
            # Wait for async download to complete
            self.wait_async_download()
        
        return self.successful
    
    def start_async_download(self):
        """Start asynchronous download in a background thread."""
        if self.download_thread is None:
            self.download_thread = threading.Thread(target=self._run_download, daemon=True)
            self.download_thread.start()
    
    def wait_async_download(self) -> bool:
        """Wait for async download to complete.
        
        Returns:
            True if download was successful
        """
        if self.download_thread:
            # Wait for thread to start
            timeout_count = 0
            while not self.started and timeout_count < 100:
                time.sleep(0.1)
                timeout_count += 1
            
            # Wait for download to complete
            self.download_thread.join()
        
        return self.successful
    
    def _run_download(self):
        """Internal method that performs the actual download."""
        with self.download_lock:
            self.started = True
            self.time_download_start = time.time()
            
            Out.debug(f"Starting download from {self.source_url}")
            
            for attempt in range(self.retries):
                try:
                    success = self._attempt_download()
                    if success:
                        self.successful = True
                        break
                    else:
                        Out.debug(f"Download attempt {attempt + 1} failed, retrying...")
                        if attempt < self.retries - 1:
                            time.sleep(1)  # Wait before retry
                except Exception as e:
                    Out.warning(f"Download attempt {attempt + 1} failed with exception: {e}")
                    if attempt < self.retries - 1:
                        time.sleep(1)  # Wait before retry
            
            self.time_download_finish = time.time()
            
            if self.successful:
                download_time = self.time_download_finish - self.time_download_start
                download_size = len(self.download_data) if self.download_data else self.content_length
                Out.debug(f"Download completed successfully in {download_time:.2f}s, {download_size} bytes")
            else:
                Out.warning(f"Download failed after {self.retries} attempts")
    
    def _attempt_download(self) -> bool:
        """Attempt to download the file once.
        
        Returns:
            True if download was successful
        """
        try:
            # Prepare request
            headers = {
                'User-Agent': f'Hentai@Home {Settings.CLIENT_VERSION}'
            }
            
            # Configure proxy if needed
            proxies = None
            if self.allow_proxy and Settings.get_image_proxy_host():
                proxy_host = Settings.get_image_proxy_host()
                proxy_port = Settings.get_image_proxy_port()
                proxy_type = Settings.get_image_proxy_type()
                if proxy_type and proxy_host:
                    proxy_url = f"{proxy_type}://{proxy_host}:{proxy_port}"
                    proxies = {'http': proxy_url, 'https': proxy_url}
            
            # Make request with streaming
            response = requests.get(
                self.source_url,
                headers=headers,
                proxies=proxies,
                timeout=self.timeout,
                stream=True
            )
            
            response.raise_for_status()
            
            # Get content length
            self.content_length = int(response.headers.get('Content-Length', 0))
            
            if self.time_first_byte == 0:
                self.time_first_byte = time.time()
            
            # Download data
            if self.output_path:
                return self._download_to_file(response)
            else:
                return self._download_to_memory(response)
        
        except Exception as e:
            Out.debug(f"Download attempt failed: {e}")
            return False
    
    def _download_to_file(self, response) -> bool:
        """Download data directly to file.
        
        Args:
            response: The requests Response object
            
        Returns:
            True if successful
        """
        try:
            # Ensure output directory exists
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            
            bytes_downloaded = 0
            chunk_size = 8192
            
            with open(self.output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        # Apply bandwidth limiting
                        if self.download_limiter:
                            self.download_limiter.wait_for_quota(threading.current_thread(), len(chunk))
                        
                        f.write(chunk)
                        bytes_downloaded += len(chunk)
                        
                        # Update progress
                        if self.progress_callback:
                            self.progress_callback(bytes_downloaded, self.content_length)
                        
                        # Check download time limit
                        if time.time() - self.time_download_start > self.max_download_time:
                            Out.warning("Download exceeded maximum time limit")
                            return False
            
            Out.debug(f"Downloaded {bytes_downloaded} bytes to {self.output_path}")
            return True
        
        except Exception as e:
            Out.warning(f"Error downloading to file: {e}")
            return False
    
    def _download_to_memory(self, response) -> bool:
        """Download data to memory.
        
        Args:
            response: The requests Response object
            
        Returns:
            True if successful
        """
        try:
            data_chunks = []
            bytes_downloaded = 0
            chunk_size = 8192
            
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    # Apply bandwidth limiting
                    if self.download_limiter:
                        self.download_limiter.wait_for_quota(threading.current_thread(), len(chunk))
                    
                    if not self.discard_data:
                        data_chunks.append(chunk)
                    
                    bytes_downloaded += len(chunk)
                    
                    # Update progress
                    if self.progress_callback:
                        self.progress_callback(bytes_downloaded, self.content_length)
                    
                    # Check download time limit
                    if time.time() - self.time_download_start > self.max_download_time:
                        Out.warning("Download exceeded maximum time limit")
                        return False
            
            if not self.discard_data:
                self.download_data = b''.join(data_chunks)
            
            Out.debug(f"Downloaded {bytes_downloaded} bytes to memory")
            return True
        
        except Exception as e:
            Out.warning(f"Error downloading to memory: {e}")
            return False
    
    def get_download_data(self) -> Optional[bytes]:
        """Get downloaded data (if downloaded to memory).
        
        Returns:
            Downloaded data or None
        """
        return self.download_data
    
    def get_content_length(self) -> int:
        """Get content length of downloaded file.
        
        Returns:
            Content length in bytes
        """
        return self.content_length
    
    def get_download_stats(self) -> dict:
        """Get download timing and performance statistics.
        
        Returns:
            Dictionary with download statistics
        """
        total_time = self.time_download_finish - self.time_download_start if self.time_download_finish > 0 else 0
        first_byte_time = self.time_first_byte - self.time_download_start if self.time_first_byte > 0 else 0
        
        download_size = len(self.download_data) if self.download_data else self.content_length
        speed_bps = download_size / total_time if total_time > 0 else 0
        
        return {
            'successful': self.successful,
            'total_time': total_time,
            'first_byte_time': first_byte_time,
            'download_size': download_size,
            'speed_bytes_per_second': speed_bps,
            'speed_kbps': speed_bps / 1024,
            'content_length': self.content_length
        }


def download_file_simple(url: str, output_path: Path, timeout: int = 30) -> bool:
    """Simple file download function.
    
    Args:
        url: URL to download
        output_path: Where to save the file
        timeout: Timeout in seconds
        
    Returns:
        True if successful
    """
    downloader = FileDownloader(url, timeout * 1000, 300000, output_path)
    return downloader.download_file()


def download_with_bandwidth_limit(url: str, output_path: Path, bandwidth_monitor: HTTPBandwidthMonitor) -> bool:
    """Download file with bandwidth limiting.
    
    Args:
        url: URL to download
        output_path: Where to save the file
        bandwidth_monitor: Bandwidth monitor to use
        
    Returns:
        True if successful
    """
    downloader = FileDownloader(url, 30000, 300000, output_path)
    downloader.set_download_limiter(bandwidth_monitor)
    return downloader.download_file()


class SimpleFileDownloader:
    """Simplified interface for common download operations."""
    
    def __init__(self):
        """Initialize simple downloader."""
        pass
    
    def download_to_memory(self, url: str, expected_size: Optional[int] = None, 
                          timeout: int = 30) -> dict:
        """
        Download a file to memory.
        
        Args:
            url: URL to download
            expected_size: Expected file size (ignored for compatibility)
            timeout: Timeout in seconds
            
        Returns:
            Dict with 'success', 'data', and 'stats' keys
        """
        try:
            downloader = FileDownloader(url, timeout * 1000, 300000, None)
            
            # Set bandwidth limiter if available
            bandwidth_monitor = HTTPBandwidthMonitor.get_instance()
            if bandwidth_monitor:
                downloader.set_download_limiter(bandwidth_monitor)
            
            success = downloader.download_file()
            
            return {
                'success': success,
                'data': downloader.get_download_data() if success else None,
                'stats': downloader.get_download_stats()
            }
            
        except Exception as e:
            Out.warning(f"SimpleFileDownloader: Error downloading {url}: {e}")
            return {
                'success': False,
                'data': None,
                'stats': {'error': str(e)}
            }
    
    def download_to_file(self, url: str, output_path: Path, timeout: int = 30) -> dict:
        """
        Download a file to disk.
        
        Args:
            url: URL to download
            output_path: Where to save the file
            timeout: Timeout in seconds
            
        Returns:
            Dict with 'success' and 'stats' keys
        """
        try:
            downloader = FileDownloader(url, timeout * 1000, 300000, output_path)
            
            # Set bandwidth limiter if available
            bandwidth_monitor = HTTPBandwidthMonitor.get_instance()
            if bandwidth_monitor:
                downloader.set_download_limiter(bandwidth_monitor)
            
            success = downloader.download_file()
            
            return {
                'success': success,
                'stats': downloader.get_download_stats()
            }
            
        except Exception as e:
            Out.warning(f"SimpleFileDownloader: Error downloading {url} to {output_path}: {e}")
            return {
                'success': False,
                'stats': {'error': str(e)}
            }
    
    def set_bandwidth_limiter(self, limiter: HTTPBandwidthMonitor):
        """Set bandwidth limiter (for compatibility - applied per download)."""
        # This is a no-op for the simple interface since each download
        # creates its own FileDownloader instance
        pass
