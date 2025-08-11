"""
Gallery Downloader for bulk downloading entire galleries.

This module provides gallery downloading functionality to improve
cache efficiency by pre-downloading entire galleries.
"""

import os
import re
import tempfile
import threading
import time
from pathlib import Path
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
import hashlib

from .out import Out
from .settings import Settings
from .file_downloader import FileDownloader
from .simple_downloader import download_file_simple
from .file_validator import FileValidator
from .http_bandwidth_monitor import HTTPBandwidthMonitor
from .stats import Stats


class GalleryFile:
    """Represents a single file in a gallery download."""
    
    # Download states
    STATE_DOWNLOAD_FAILED = 0
    STATE_DOWNLOAD_SUCCESSFUL = 1
    STATE_ALREADY_DOWNLOADED = 2
    
    def __init__(self, page: int, fileindex: int, xres: str, expected_sha1_hash: Optional[str], 
                 filetype: str, filename: str, todir: Path, downloader: 'GalleryDownloader'):
        """Initialize a gallery file.
        
        Args:
            page: Page number in gallery
            fileindex: File index
            xres: Resolution (e.g., 'org', '1280', etc.)
            expected_sha1_hash: Expected SHA1 hash (None if unknown)
            filetype: File extension
            filename: Base filename
            todir: Target directory
            downloader: Parent GalleryDownloader instance
        """
        self.page = page
        self.fileindex = fileindex
        self.xres = xres
        self.expected_sha1_hash = expected_sha1_hash
        self.filetype = filetype
        self.filename = filename
        self.todir = todir
        self.downloader = downloader
        
        # State
        self.file_retry = 0
        self.file_complete = False
        self.tofile = todir / f"{filename}.{filetype}"
    
    def download(self) -> int:
        """Download this file.
        
        Returns:
            Download state constant
        """
        if self.file_complete:
            return self.STATE_ALREADY_DOWNLOADED
        
        # Check if file already exists and validate
        if self.tofile.exists():
            verified = False
            
            if self.tofile.stat().st_size > 0:
                try:
                    if self.expected_sha1_hash is None:
                        # If file was generated on-demand, we can't verify hash
                        verified = True
                    else:
                        validator = FileValidator.get_instance()
                        if validator.validate_file(self.tofile, self.expected_sha1_hash):
                            verified = True
                            Out.debug(f"GalleryDownloader: Verified SHA-1 hash for {self}: {self.expected_sha1_hash}")
                except Exception as e:
                    Out.warning(f"GalleryDownloader: Error validating {self.tofile}: {e}")
            
            if verified:
                self.file_complete = True
                return self.STATE_ALREADY_DOWNLOADED
            else:
                # Remove invalid file
                try:
                    self.tofile.unlink()
                except Exception as e:
                    Out.warning(f"GalleryDownloader: Could not remove invalid file {self.tofile}: {e}")
        
        # Get download URL from server
        client = self.downloader.client
        if not client or not client.get_server_handler():
            Out.warning("GalleryDownloader: No server handler available")
            return self.STATE_DOWNLOAD_FAILED
        
        self.file_retry += 1
        source_url = client.get_server_handler().get_downloader_fetch_url(
            self.downloader.gid, self.page, self.fileindex, self.xres, self.file_retry
        )
        
        if not source_url:
            Out.warning(f"GalleryDownloader: No download URL available for {self}")
            return self.STATE_DOWNLOAD_FAILED
        
        try:
            # Use FileDownloader for the actual download
            downloader = FileDownloader(
                source_url=source_url,
                timeout=10000,
                max_download_time=300000,
                output_path=self.tofile,
                allow_proxy=(self.file_retry > 1)
            )
            
            # Set bandwidth limiter if available
            if self.downloader.download_limiter:
                downloader.set_download_limiter(self.downloader.download_limiter)
            
            # Start download
            self.file_complete = downloader.download_file()
            
            # Validate downloaded file if we have expected hash
            if self.file_complete and self.expected_sha1_hash:
                validator = FileValidator.get_instance()
                if not validator.validate_file(self.tofile, self.expected_sha1_hash):
                    self.file_complete = False
                    Out.debug(f"GalleryDownloader: Corrupted download for {self}, forcing retry")
                    try:
                        self.tofile.unlink()
                    except:
                        pass
                else:
                    Out.debug(f"GalleryDownloader: Verified SHA-1 hash for {self}: {self.expected_sha1_hash}")
            
        except Exception as e:
            Out.warning(f"GalleryDownloader: Error downloading {self.tofile}: {e}")
            self.file_complete = False
        
        Out.debug(f"GalleryDownloader: Download of {self} {'successful' if self.file_complete else 'FAILED'} (attempt={self.file_retry})")
        
        if self.file_complete:
            Stats.get_instance().increment_files_received()
            Out.info(f"GalleryDownloader: Finished downloading gid={self.downloader.gid} page={self.page}: {self.filename}.{self.filetype}")
        else:
            # Log failure for reporting
            parsed_url = urlparse(source_url)
            failure_key = f"{parsed_url.hostname}-{self.fileindex}-{self.xres}"
            self.downloader.log_failure(failure_key)
            
            # Clean up failed download
            if self.tofile.exists():
                try:
                    self.tofile.unlink()
                except:
                    pass
        
        return self.STATE_DOWNLOAD_SUCCESSFUL if self.file_complete else self.STATE_DOWNLOAD_FAILED
    
    def __str__(self) -> str:
        return (f"gid={self.downloader.gid} page={self.page} fileindex={self.fileindex} "
                f"xres={self.xres} filetype={self.filetype} filename={self.filename}")


class GalleryDownloader:
    """Downloads entire galleries for improved cache efficiency."""
    
    def __init__(self, client):
        """Initialize the gallery downloader.
        
        Args:
            client: The HentaiAtHomeClient instance
        """
        self.client = client
        self.validator = FileValidator.get_instance()
        
        # Bandwidth limiting (only if not disabled)
        self.download_limiter = None
        if not Settings.get_bool('disable_download_bwm', False):
            self.download_limiter = HTTPBandwidthMonitor.get_instance()
        
        # Thread management
        self.my_thread = None
        self.downloads_available = True
        self.pending_download = False
        self.mark_downloaded = False
        
        # Current gallery state
        self.gid = 0
        self.filecount = 0
        self.minxres = None
        self.title = None
        self.information = ""
        self.gallery_files: Optional[List[GalleryFile]] = None
        self.todir: Optional[Path] = None
        self.failures: Optional[List[str]] = None
        
        # Start download thread
        self.my_thread = threading.Thread(target=self.run, daemon=True)
        self.my_thread.start()
    
    def run(self):
        """Main download loop."""
        while not self.client.is_shutting_down() and self.downloads_available:
            if not self.pending_download:
                self.pending_download = self.initialize_new_gallery_meta()
            
            if not self.pending_download:
                self.downloads_available = False
                break
            
            Out.info(f"GalleryDownloader: Starting download of gallery: {self.title}")
            
            gallery_retry = 0
            total_failed_files = 0
            success = False
            
            while not success and gallery_retry < 10 and total_failed_files < self.filecount * 2:
                gallery_retry += 1
                successful_files = 0
                
                for gfile in self.gallery_files:
                    if self.client.is_shutting_down():
                        break
                    
                    sleep_time = 0
                    
                    if self.client.is_suspended():
                        sleep_time = 60  # 60 seconds
                    elif self.download_directory_has_low_space():
                        Out.warning("GalleryDownloader: Download suspended; low disk space")
                        sleep_time = 300  # 5 minutes
                    else:
                        download_state = gfile.download()
                        
                        if download_state == GalleryFile.STATE_DOWNLOAD_SUCCESSFUL:
                            successful_files += 1
                            sleep_time = 1  # 1 second between downloads
                        elif download_state == GalleryFile.STATE_ALREADY_DOWNLOADED:
                            successful_files += 1
                        elif download_state == GalleryFile.STATE_DOWNLOAD_FAILED:
                            total_failed_files += 1
                            sleep_time = 5  # 5 seconds after failure
                    
                    if sleep_time > 0:
                        try:
                            time.sleep(sleep_time)
                        except:
                            break
                
                if successful_files == self.filecount:
                    success = True
            
            self.finalize_gallery_download(success)
        
        Out.info("GalleryDownloader: Download thread finished.")
        self.client.delete_downloader()
    
    def download_directory_has_low_space(self) -> bool:
        """Check if download directory has low disk space.
        
        Returns:
            True if space is low
        """
        if Settings.get_bool('skip_free_space_check', False):
            return False
        
        try:
            download_dir = Settings.get_download_dir()
            if not download_dir.exists():
                return True
            
            free_space = os.statvfs(download_dir).f_bavail * os.statvfs(download_dir).f_frsize
            min_required = Settings.get_int('disk_min_remaining_bytes', 1073741824)  # 1GB default
            
            return free_space < (min_required + 1048576000)  # +1GB buffer
            
        except Exception as e:
            Out.warning(f"GalleryDownloader: Could not check disk space: {e}")
            return False
    
    def finalize_gallery_download(self, success: bool):
        """Finalize the gallery download.
        
        Args:
            success: Whether the download was successful
        """
        self.pending_download = False
        self.mark_downloaded = True
        
        if success:
            Out.info(f"GalleryDownloader: Finished download of gallery: {self.title}")
            
            # Write gallery info file
            try:
                if self.todir and self.information:
                    info_file = self.todir / "galleryinfo.txt"
                    info_file.write_text(self.information, encoding='utf-8')
            except Exception as e:
                Out.warning(f"GalleryDownloader: Could not write galleryinfo file: {e}")
        else:
            Out.warning(f"GalleryDownloader: Permanently failed downloading gallery: {self.title}")
    
    def initialize_new_gallery_meta(self) -> bool:
        """Initialize metadata for a new gallery download.
        
        Returns:
            True if successful
        """
        # Report failures from previous download
        if self.mark_downloaded and self.failures:
            server_handler = self.client.get_server_handler()
            if server_handler:
                server_handler.report_downloader_failures(self.failures)
        
        # Build metadata request URL
        try:
            rpc_host = Settings.get_rpc_server_host()
            if not rpc_host:
                Out.warning("GalleryDownloader: No RPC server host available")
                return False
            
            # Format query parameter
            query_param = ""
            if self.mark_downloaded:
                query_param = f"{self.gid};{self.minxres}" if self.gid and self.minxres else ""
            
            server_handler = self.client.get_server_handler()
            if not server_handler:
                Out.warning("GalleryDownloader: No server handler available")
                return False
            
            query_string = server_handler.get_url_query_string("fetchqueue", query_param)
            meta_url = f"{Settings.CLIENT_RPC_PROTOCOL}{rpc_host}/15/dl?{query_string}"
            
        except Exception as e:
            Out.warning(f"GalleryDownloader: Error building metadata URL: {e}")
            return False
        
        # Download metadata
        try:
            # Use simple file downloader to get metadata
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_file:
                tmp_path = Path(tmp_file.name)
            
            try:
                success = download_file_simple(meta_url, tmp_path, timeout=30)
                if not success or not tmp_path.exists():
                    return False
                
                gallery_meta = tmp_path.read_text(encoding='utf-8')
                
            finally:
                if tmp_path.exists():
                    tmp_path.unlink()
            
        except Exception as e:
            Out.warning(f"GalleryDownloader: Error downloading metadata: {e}")
            return False
        
        # Check response
        if not gallery_meta:
            return False
        
        if gallery_meta.strip() == "INVALID_REQUEST":
            Out.warning("GalleryDownloader: Request was rejected by the server")
            return False
        
        if gallery_meta.strip() == "NO_PENDING_DOWNLOADS":
            return False
        
        Out.debug("GalleryDownloader: Started gallery metadata parsing")
        
        # Reset state
        self.gid = 0
        self.filecount = 0
        self.minxres = None
        self.title = None
        self.information = ""
        self.gallery_files = None
        self.todir = None
        self.mark_downloaded = False
        self.failures = None
        
        # Parse metadata
        return self.parse_gallery_metadata(gallery_meta)
    
    def parse_gallery_metadata(self, gallery_meta: str) -> bool:
        """Parse gallery metadata.
        
        Args:
            gallery_meta: Raw metadata string
            
        Returns:
            True if parsing successful
        """
        parse_state = 0  # 0=header, 1=filelist, 2=information
        
        try:
            for line in gallery_meta.split('\n'):
                line = line.strip()
                
                if line == "FILELIST" and parse_state == 0:
                    parse_state = 1
                    continue
                
                if line == "INFORMATION" and parse_state == 1:
                    parse_state = 2
                    continue
                
                if parse_state < 2 and not line:
                    continue
                
                if parse_state == 0:
                    # Header parsing
                    parts = line.split(' ', 1)
                    if len(parts) != 2:
                        continue
                    
                    key, value = parts
                    
                    if key == "GID":
                        self.gid = int(value)
                        Out.debug(f"GalleryDownloader: Parsed gid={self.gid}")
                    
                    elif key == "FILECOUNT":
                        self.filecount = int(value)
                        self.gallery_files = [None] * self.filecount
                        Out.debug(f"GalleryDownloader: Parsed filecount={self.filecount}")
                    
                    elif key == "MINXRES":
                        if re.match(r'^(org|\d+)$', value):
                            self.minxres = value
                            Out.debug(f"GalleryDownloader: Parsed minxres={self.minxres}")
                        else:
                            raise ValueError("Invalid minxres")
                    
                    elif key == "TITLE":
                        # Clean title for filesystem use
                        self.title = re.sub(r'[*"\\<>:|?]', '', value)
                        self.title = re.sub(r'\s+', ' ', self.title).strip()
                        Out.debug(f"GalleryDownloader: Parsed title={self.title}")
                        
                        # Create download directory
                        self.create_download_directory()
                
                elif parse_state == 1:
                    # File list parsing
                    # Format: page fileindex xres sha1hash filetype filename
                    parts = line.split(' ', 5)
                    if len(parts) != 6:
                        continue
                    
                    page = int(parts[0])
                    fileindex = int(parts[1])
                    xres = parts[2]
                    sha1hash = None if parts[3] == "unknown" else parts[3]
                    filetype = parts[4]
                    filename = parts[5]
                    
                    gf = GalleryFile(page, fileindex, xres, sha1hash, filetype, filename, self.todir, self)
                    
                    if 1 <= page <= self.filecount:
                        self.gallery_files[page - 1] = gf
                        Out.debug(f"GalleryDownloader: Parsed file {gf}")
                
                else:
                    # Information section
                    self.information += line + '\n'
        
        except Exception as e:
            Out.warning(f"GalleryDownloader: Failed to parse metadata: {e}")
            return False
        
        # Validate parsed data
        return (self.gid > 0 and self.filecount > 0 and self.minxres and 
                self.title and self.todir and self.gallery_files and
                all(gf is not None for gf in self.gallery_files))
    
    def create_download_directory(self):
        """Create the download directory for this gallery."""
        if not self.title or not self.gid or not self.minxres:
            return
        
        # Create directory name
        xres_suffix = "" if self.minxres == "org" else f"-{self.minxres}x"
        postfix = f" [{self.gid}{xres_suffix}]"
        
        # Handle filename length limits
        max_filename_length = Settings.get_int('max_filename_length', 125)
        title_length = len(self.title)
        postfix_length = len(postfix)
        
        if title_length + postfix_length > max_filename_length:
            # Truncate title if too long
            max_title_length = max_filename_length - postfix_length - 3  # 3 for "..."
            truncated_title = self.title[:max_title_length]
            Out.debug(f"Truncated title from {title_length} to {len(truncated_title)} characters")
            directory_name = f"{truncated_title}...{postfix}"
        else:
            directory_name = f"{self.title}{postfix}"
        
        # Create directory path
        download_dir = Settings.get_download_dir()
        self.todir = download_dir / directory_name
        
        # Security check for directory traversal
        try:
            if not self.todir.resolve().parent.samefile(download_dir.resolve()):
                Out.warning("GalleryDownloader: Unexpected download location detected")
                self.todir = None
                return
        except Exception:
            Out.warning("GalleryDownloader: Could not verify download location")
            self.todir = None
            return
        
        # Create directory
        try:
            self.todir.mkdir(parents=True, exist_ok=True)
            Out.debug(f"GalleryDownloader: Created directory {self.todir}")
        except Exception as e:
            Out.warning(f"GalleryDownloader: Could not create directory '{directory_name}': {e}")
            # Fallback to simple directory name
            try:
                fallback_name = f"{self.gid}{xres_suffix}"
                self.todir = download_dir / fallback_name
                self.todir.mkdir(parents=True, exist_ok=True)
                Out.debug(f"GalleryDownloader: Created fallback directory {self.todir}")
            except Exception as e2:
                Out.warning(f"GalleryDownloader: Could not create fallback directory: {e2}")
                self.todir = None
    
    def log_failure(self, failure_key: str):
        """Log a download failure for reporting.
        
        Args:
            failure_key: Failure identifier
        """
        if self.failures is None:
            self.failures = []
        
        if failure_key not in self.failures:
            self.failures.append(failure_key)
    
    def shutdown(self):
        """Shutdown the gallery downloader."""
        self.downloads_available = False
        if self.my_thread and self.my_thread.is_alive():
            self.my_thread.join(timeout=5.0)


# Remove the duplicate import at the bottom
