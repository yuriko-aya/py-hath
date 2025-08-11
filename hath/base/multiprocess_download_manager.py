"""
Multiprocess download manager implementation.
"""

import queue
import time
import threading
from typing import Dict, Any, List

from .out import Out
from .settings import Settings


class MultiprocessDownloadManager:
    """Download manager for multiprocess environment."""
    
    def __init__(self, shared_resources):
        """Initialize multiprocess download manager."""
        self.shared = shared_resources
        self.shutdown_flag = False
        self.heartbeat_thread = None
        self.download_threads = []
        self.max_concurrent_downloads = 4
        
        # Download queues
        self.gallery_queue = queue.Queue(maxsize=100)
        self.proxy_queue = queue.Queue(maxsize=50)
        
        # Statistics
        self.downloads_completed = 0
        self.downloads_failed = 0
        self.bytes_downloaded = 0
    
    def run(self):
        """Run the download manager."""
        try:
            Out.info("Starting multiprocess download manager...")
            
            # Start heartbeat thread
            self._start_heartbeat()
            
            # Start download worker threads
            self._start_download_workers()
            
            # Main loop
            self._main_loop()
            
        except Exception as e:
            Out.error(f"Download manager error: {e}")
            self.shared.command_queue.put({
                'type': 'shutdown_request',
                'process': 'download_manager',
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
                        'process': 'download_manager',
                        'timestamp': time.time()
                    }, block=False)
                except queue.Full:
                    pass  # Skip if queue is full
                
                time.sleep(10)  # Send heartbeat every 10 seconds
        
        self.heartbeat_thread = threading.Thread(target=heartbeat_worker, daemon=True)
        self.heartbeat_thread.start()
    
    def _start_download_workers(self):
        """Start download worker threads."""
        for i in range(self.max_concurrent_downloads):
            worker = threading.Thread(
                target=self._download_worker,
                args=(f"worker_{i}",),
                daemon=True
            )
            worker.start()
            self.download_threads.append(worker)
        
        Out.info(f"Started {self.max_concurrent_downloads} download workers")
    
    def _download_worker(self, worker_name: str):
        """Download worker thread."""
        Out.debug(f"Download worker {worker_name} started")
        
        while not self.shutdown_flag and not self.shared.shutdown_event.is_set():
            try:
                # Check for download requests from shared queue
                try:
                    download_request = self.shared.download_queue.get(timeout=1.0)
                    self._process_download_request(download_request, worker_name)
                except queue.Empty:
                    continue
                
                # Check for gallery downloads
                try:
                    gallery_request = self.gallery_queue.get_nowait()
                    self._process_gallery_request(gallery_request, worker_name)
                except queue.Empty:
                    pass
                
                # Check for proxy downloads
                try:
                    proxy_request = self.proxy_queue.get_nowait()
                    self._process_proxy_request(proxy_request, worker_name)
                except queue.Empty:
                    pass
                
            except Exception as e:
                Out.warning(f"Download worker {worker_name} error: {e}")
                time.sleep(1)
        
        Out.debug(f"Download worker {worker_name} exiting")
    
    def _process_download_request(self, request: Dict[str, Any], worker_name: str):
        """Process a download request."""
        request_type = request.get('type', 'unknown')
        
        if request_type == 'gallery':
            self._process_gallery_request(request, worker_name)
        elif request_type == 'proxy':
            self._process_proxy_request(request, worker_name)
        else:
            Out.warning(f"Unknown download request type: {request_type}")
    
    def _process_gallery_request(self, request: Dict[str, Any], worker_name: str):
        """Process a gallery download request."""
        try:
            gallery_id = request.get('gallery_id')
            files = request.get('files', [])
            
            Out.info(f"Worker {worker_name} downloading gallery {gallery_id} ({len(files)} files)")
            
            for file_info in files:
                if self.shutdown_flag or self.shared.shutdown_event.is_set():
                    break
                
                success = self._download_file(file_info, worker_name)
                
                if success:
                    self.downloads_completed += 1
                    self._update_cache_index(file_info)
                else:
                    self.downloads_failed += 1
                
                # Update stats
                self._send_download_stats()
            
            Out.info(f"Worker {worker_name} completed gallery {gallery_id}")
            
        except Exception as e:
            Out.error(f"Error processing gallery request: {e}")
    
    def _process_proxy_request(self, request: Dict[str, Any], worker_name: str):
        """Process a proxy download request."""
        try:
            file_id = request.get('file_id')
            sources = request.get('sources', [])
            
            Out.debug(f"Worker {worker_name} downloading proxy file {file_id}")
            
            success = self._download_proxy_file(file_id, sources, worker_name)
            
            if success:
                self.downloads_completed += 1
                # File info would be passed in the request in a real implementation
                file_info = {'file_id': file_id, 'size': 0, 'hash': ''}
                self._update_cache_index(file_info)
            else:
                self.downloads_failed += 1
            
            # Update stats
            self._send_download_stats()
            
        except Exception as e:
            Out.error(f"Error processing proxy request: {e}")
    
    def _download_file(self, file_info: Dict[str, Any], worker_name: str) -> bool:
        """Download a single file."""
        try:
            file_id = file_info.get('file_id')
            url = file_info.get('url')
            expected_size = file_info.get('size', 0)
            expected_hash = file_info.get('hash', '')
            
            Out.debug(f"Worker {worker_name} downloading {file_id} from {url}")
            
            # Simulate download (in real implementation, use requests)
            import requests
            import hashlib
            from pathlib import Path
            
            # Download file
            response = requests.get(url, timeout=30)
            if response.status_code != 200:
                Out.warning(f"Download failed with status {response.status_code}")
                return False
            
            file_data = response.content
            
            # Validate size
            if expected_size > 0 and len(file_data) != expected_size:
                Out.warning(f"File size mismatch: {len(file_data)} != {expected_size}")
                return False
            
            # Validate hash
            if expected_hash:
                actual_hash = hashlib.sha1(file_data).hexdigest()
                if actual_hash != expected_hash:
                    Out.warning(f"File hash mismatch: {actual_hash} != {expected_hash}")
                    return False
            
            # Save to cache
            cache_path = self._get_cache_path(file_id)
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_bytes(file_data)
            
            self.bytes_downloaded += len(file_data)
            
            Out.debug(f"Worker {worker_name} successfully downloaded {file_id}")
            return True
            
        except Exception as e:
            Out.warning(f"Error downloading file {file_info.get('file_id', 'unknown')}: {e}")
            return False
    
    def _download_proxy_file(self, file_id: str, sources: List[str], worker_name: str) -> bool:
        """Download a proxy file."""
        # Similar to _download_file but for proxy sources
        for source_url in sources:
            try:
                # Attempt download from this source
                # This would use the same logic as _download_file
                Out.debug(f"Worker {worker_name} trying proxy source {source_url}")
                
                # Placeholder - in real implementation, download and validate
                return True
                
            except Exception as e:
                Out.warning(f"Failed to download from {source_url}: {e}")
                continue
        
        return False
    
    def _get_cache_path(self, file_id: str) -> Path:
        """Get cache path for a file."""
        cache_dir = Settings.get_cache_dir()
        if len(file_id) >= 2:
            subdir = file_id[:2]
            return cache_dir / subdir / file_id
        else:
            return cache_dir / file_id
    
    def _update_cache_index(self, file_info: Dict[str, Any]):
        """Update shared cache index."""
        try:
            with self.shared.cache_lock:
                cache_entry = {
                    'file_id': file_info['file_id'],
                    'size': file_info.get('size', 0),
                    'hash': file_info.get('hash', ''),
                    'last_accessed': time.time(),
                    'downloaded_by': 'download_manager'
                }
                self.shared.cache_index[file_info['file_id']] = cache_entry
                
                # Update cache stats
                self.shared.cache_stats['file_count'] = len(self.shared.cache_index)
                self.shared.cache_stats['total_size'] = sum(
                    entry.get('size', 0) for entry in self.shared.cache_index.values()
                )
                self.shared.cache_stats['last_update'] = time.time()
            
        except Exception as e:
            Out.warning(f"Error updating cache index: {e}")
    
    def _send_download_stats(self):
        """Send download statistics to main process."""
        try:
            self.shared.stats_queue.put({
                'type': 'download_stats',
                'downloads_completed': self.downloads_completed,
                'downloads_failed': self.downloads_failed,
                'bytes_downloaded': self.bytes_downloaded,
                'timestamp': time.time()
            }, block=False)
        except queue.Full:
            pass  # Skip if queue is full
    
    def _main_loop(self):
        """Main download manager loop."""
        Out.info("Download manager ready")
        
        while not self.shutdown_flag and not self.shared.shutdown_event.is_set():
            try:
                # Check for commands from main process
                self._process_commands()
                
                # Perform periodic maintenance
                self._perform_maintenance()
                
                time.sleep(5)  # Main loop iteration delay
                
            except Exception as e:
                Out.warning(f"Download manager main loop error: {e}")
                time.sleep(1)
    
    def _process_commands(self):
        """Process commands from main process."""
        # This would process commands like "start gallery download", "stop downloads", etc.
        pass
    
    def _perform_maintenance(self):
        """Perform periodic maintenance tasks."""
        # This would include cleaning up completed downloads, updating statistics, etc.
        pass
    
    def _cleanup(self):
        """Cleanup download manager resources."""
        self.shutdown_flag = True
        
        # Wait for download threads to finish
        for thread in self.download_threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        Out.info("Download manager cleanup complete")
