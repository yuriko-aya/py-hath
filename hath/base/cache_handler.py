"""
Cache handler for managing local file cache.
"""

import os
import pickle
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Set

from .out import Out
from .settings import Settings
from .tools import Tools


class HVFile:
    """Represents a cached file with validation."""
    
    def __init__(self, file_id: str, size: int, sha1_hash: str):
        """Initialize HV file."""
        self.file_id = file_id
        self.size = size
        self.sha1_hash = sha1_hash
        self.last_accessed = time.time()
    
    def get_local_file_ref(self) -> Path:
        """Get the local file path for this cached file."""
        # Files are stored in subdirectories based on first 2 characters of file_id
        if len(self.file_id) >= 2:
            subdir = self.file_id[:2]
            cache_dir = Settings.get_cache_dir()
            return cache_dir / subdir / self.file_id
        else:
            cache_dir = Settings.get_cache_dir()
            return cache_dir / self.file_id
    
    def get_static_range(self) -> str:
        """Get the static range for this file."""
        return self.file_id[:2] if len(self.file_id) >= 2 else ""
    
    def is_valid(self) -> bool:
        """Check if the cached file is valid."""
        file_path = self.get_local_file_ref()
        
        if not file_path.exists():
            return False
        
        # Check file size
        if Tools.get_file_size(file_path) != self.size:
            return False
        
        # Check SHA1 hash if verification is enabled
        if not Settings.is_disable_file_verification():
            file_hash = Tools.get_file_sha1(file_path)
            if file_hash != self.sha1_hash:
                return False
        
        return True


class CacheHandler:
    """Manages the local file cache."""
    
    LRU_CACHE_SIZE = 1048576
    
    def __init__(self, client):
        """Initialize the cache handler."""
        self.client = client
        self.cache_dir = Settings.get_cache_dir()
        
        # Cache state
        self.cache_count = 0
        self.cache_size = 0
        self.cache_loaded = False
        
        # LRU cache management (matching Java implementation)
        self.lru_cache_table: Optional[list] = None  # Will be list of shorts (0-65535) in Python
        self.lru_clear_pointer = 0
        self.lru_skip_check_cycle = 0
        
        # Static range tracking (matching Java Hashtable<String,Long>)
        self.static_range_oldest: Dict[str, int] = {}
        
        # File verification
        self.last_file_verification = 0
        
        # Threading
        self.lock = threading.Lock()
        
        # Cache pruning
        self.prune_aggression = 1
        
        self._initialize_cache()
    
    def _initialize_cache(self):
        """Initialize the cache system."""
        Out.info("CacheHandler: Initializing the cache system...")
        
        # Clean up temporary files
        self._cleanup_temp_files()
        
        # Try to load persistent cache data
        fast_startup = False
        if not Settings._rescan_cache:
            Out.info("CacheHandler: Attempting to load persistent cache data...")
            if self._load_persistent_data():
                Out.info("CacheHandler: Successfully loaded persistent cache data")
                fast_startup = True
            else:
                Out.info("CacheHandler: Persistent cache data is not available")
        
        # Delete persistent data (it's loaded now)
        self._delete_persistent_data()
        
        if not fast_startup:
            Out.info("CacheHandler: Performing cache cleanup and initialization...")
            
            # Initialize LRU cache table like Java (array of shorts)
            self.lru_clear_pointer = 0
            self.cache_count = 0
            self.cache_size = 0
            
            # Initialize static range tracking like Java
            # Hashtable<String,Long> with capacity for static ranges * 1.5
            self.static_range_oldest = {}
            
            # Initialize LRU cache table (1048576 shorts)
            self.lru_cache_table = [0] * self.LRU_CACHE_SIZE
            
            # Cleanup and reorganize cache
            self._startup_cache_cleanup()
            
            if self.client.is_shutting_down():
                return
            
            # Initialize cache from existing files
            self._startup_init_cache()
        
        # Check if we have static ranges but no cached files (indicating a potential issue)
        if self.cache_count == 0 and Settings.get_static_range_count() > 0:
            # This is actually a warning, not an error - it's normal for a new client
            Out.warning(f"CacheHandler: Client has {Settings.get_static_range_count()} static ranges assigned, but cache is empty")
            Out.warning("This is normal for a new client. Files will be cached as requests are received.")
        
        # Check for inconsistent state: files in cache dir but zero count (indicates persistent data corruption)
        if self.cache_count == 0:
            # Quick check if there are actually files in cache directories
            actual_file_count = 0
            for cache_dir in Tools.list_sorted_dirs(self.cache_dir):
                if Settings.is_static_range(cache_dir.name):
                    files = Tools.list_sorted_files(cache_dir)
                    actual_file_count += len([f for f in files if f.is_file()])
            
            if actual_file_count > 0:
                Out.warning(f"CacheHandler: Found {actual_file_count} files on disk but cache count is 0")
                Out.warning("This indicates persistent cache data corruption. Rescanning cache...")
                # Force rescan by calling _startup_init_cache again
                self._startup_init_cache()
        
        # Prune cache if over limit
        cache_limit = Settings.get_disk_limit_bytes()
        if self.get_cache_size_with_overhead() > cache_limit:
            Out.info("CacheHandler: We are over the cache limit, pruning until the limit is met")
            self._prune_cache_to_limit(cache_limit)
        
        self.cache_loaded = True
        Out.info("CacheHandler: Cache initialization completed")
    
    def _cleanup_temp_files(self):
        """Clean up orphaned temporary files."""
        temp_dir = Settings.get_temp_dir()
        for temp_file in temp_dir.iterdir():
            if temp_file.is_file():
                # Don't delete log files or other important files
                if not temp_file.name.startswith(('log_', 'pcache_')) and temp_file.name != 'client_login':
                    Out.debug(f"CacheHandler: Deleted orphaned temporary file {temp_file}")
                    Tools.safe_delete_file(temp_file)
            else:
                Out.warning(f"CacheHandler: Found a non-file {temp_file} in the temp directory, won't delete.")
    
    def _startup_cache_cleanup(self):
        """Perform startup cache cleanup and reorganization."""
        Out.info("CacheHandler: Cache cleanup pass...")
        
        l1_dirs = Tools.list_sorted_dirs(self.cache_dir)
        
        if len(l1_dirs) > Settings.get_static_range_count():
            Out.warning(f"WARNING: There are {len(l1_dirs)} directories in the cache directory, "
                       f"but the server has only assigned us {Settings.get_static_range_count()} static ranges.")
            Out.warning("If this is NOT expected, please close H@H with Ctrl+C before this timeout expires.")
            Out.warning("Waiting 30 seconds before proceeding with cache cleanup...")
            time.sleep(30)
        
        if self.client.is_shutting_down():
            return
        
        # Process each level 1 directory
        checked_counter = 0
        checked_counter_pct = 0
        
        for l1_dir in l1_dirs:
            if self.client.is_shutting_down():
                break
            
            # Check if this is a valid static range directory
            if not Settings.is_static_range(l1_dir.name):
                Out.debug(f"CacheHandler: Removing invalid static range directory {l1_dir}")
                try:
                    # Remove the entire directory
                    import shutil
                    shutil.rmtree(l1_dir)
                except Exception as e:
                    Out.warning(f"Failed to remove directory {l1_dir}: {e}")
            
            checked_counter += 1
            
            # Progress reporting
            if len(l1_dirs) > 9:
                progress = checked_counter * 100 // len(l1_dirs)
                if progress >= checked_counter_pct + 10:
                    checked_counter_pct += 10
                    Out.info(f"CacheHandler: Cleanup pass at {checked_counter_pct}%")
    
    def _startup_init_cache(self):
        """Initialize cache from existing files on disk."""
        Out.info("CacheHandler: Scanning cache files...")
        
        self.lru_clear_pointer = 0
        self.cache_count = 0
        self.cache_size = 0
        
        cache_dirs = Tools.list_sorted_dirs(self.cache_dir)
        
        for cache_dir in cache_dirs:
            if self.client.is_shutting_down():
                break
            
            if not Settings.is_static_range(cache_dir.name):
                continue
            
            files = Tools.list_sorted_files(cache_dir)
            
            if not files:
                # Remove empty directory
                try:
                    cache_dir.rmdir()
                except Exception:
                    pass
                continue
            
            oldest_last_modified = time.time() * 1000
            
            for file_path in files:
                if not file_path.is_file():
                    continue
                
                hv_file = self._get_hv_file_from_file(file_path)
                
                if hv_file is None:
                    Out.debug(f"CacheHandler: The file {file_path} was corrupt.")
                    Tools.safe_delete_file(file_path)
                elif not Settings.is_static_range(hv_file.get_static_range()):
                    Out.debug(f"CacheHandler: The file {file_path} was not in an active static range.")
                    Tools.safe_delete_file(file_path)
                else:
                    self._add_file_to_active_cache(hv_file)
                    file_last_modified = file_path.stat().st_mtime * 1000
                    if file_last_modified < oldest_last_modified:
                        oldest_last_modified = file_last_modified
            
            # Update static range oldest timestamp
            if cache_dir.name not in self.static_range_oldest:
                self.static_range_oldest[cache_dir.name] = int(oldest_last_modified)
        
        Out.info(f"CacheHandler: Found {self.cache_count} files totaling {Tools.format_bytes(self.cache_size)}")
    
    def _get_hv_file_from_file(self, file_path: Path) -> Optional[HVFile]:
        """Create an HVFile object from a file on disk."""
        try:
            file_id = file_path.name
            size = Tools.get_file_size(file_path)
            
            # Calculate SHA1 hash
            sha1_hash = Tools.get_file_sha1(file_path)
            if sha1_hash is None:
                return None
            
            return HVFile(file_id, size, sha1_hash)
        except Exception:
            return None
    
    def _add_file_to_active_cache(self, hv_file: HVFile):
        """Add a file to the active cache tracking."""
        with self.lock:
            self.cache_count += 1
            self.cache_size += hv_file.size
    
    def _prune_cache_to_limit(self, limit: int):
        """Prune cache until it's under the specified limit."""
        if limit <= 0:
            Out.warning("CacheHandler: Invalid cache limit (0 or negative), skipping pruning")
            return
            
        iterations = 0
        
        while self.get_cache_size_with_overhead() > limit:
            if iterations % 100 == 0:
                current_size = self.get_cache_size_with_overhead()
                percentage = 100.0 * current_size / limit
                Out.info(f"CacheHandler: Cache is currently at {percentage:.2f}% ({Tools.format_bytes(current_size)} / {Tools.format_bytes(limit)})")
            
            # Simple pruning strategy: remove oldest files
            # In a real implementation, this would be more sophisticated
            if not self._prune_oldest_file():
                Out.warning("CacheHandler: No more files to prune, stopping")
                break
            
            iterations += 1
            
            if not self.recheck_free_disk_space():
                Out.warning("CacheHandler: Disk space check failed, stopping pruning")
                break
        
        final_size = self.get_cache_size_with_overhead()
        final_percentage = 100.0 * final_size / limit if limit > 0 else 0
        Out.info(f"CacheHandler: Finished startup cache pruning - cache now at {final_percentage:.2f}% ({Tools.format_bytes(final_size)} / {Tools.format_bytes(limit)})")
    
    def _prune_oldest_file(self) -> bool:
        """Remove the oldest file from cache. Returns True if a file was removed."""
        # This is a simplified implementation
        # In reality, this would use LRU cache management
        
        oldest_file = None
        oldest_time = float('inf')
        
        # Find oldest file
        for cache_dir in Tools.list_sorted_dirs(self.cache_dir):
            if not Settings.is_static_range(cache_dir.name):
                continue
            
            for file_path in Tools.list_sorted_files(cache_dir):
                try:
                    mtime = file_path.stat().st_mtime
                    if mtime < oldest_time:
                        oldest_time = mtime
                        oldest_file = file_path
                except Exception:
                    continue
        
        if oldest_file:
            try:
                file_size = Tools.get_file_size(oldest_file)
                Tools.safe_delete_file(oldest_file)
                
                with self.lock:
                    self.cache_count -= 1
                    self.cache_size -= file_size
                
                Out.debug(f"CacheHandler: Pruned file {oldest_file}")
                return True
            except Exception as e:
                Out.warning(f"Failed to prune file {oldest_file}: {e}")
        
        return False
    
    def get_cache_size_with_overhead(self) -> int:
        """Get cache size including filesystem overhead."""
        # Add 10% overhead for filesystem metadata
        if self.cache_size is None:
            self.cache_size = 0
        return int(self.cache_size * 1.1)
    
    def recheck_free_disk_space(self) -> bool:
        """Check if there's enough free disk space."""
        try:
            free_space = Tools.get_free_disk_space(self.cache_dir)
            required_space = 100 * 1024 * 1024  # 100MB minimum
            
            if free_space < required_space:
                Out.warning(f"Low disk space: {Tools.format_bytes(free_space)} free")
                return False
            
            return True
        except Exception as e:
            Out.warning(f"Failed to check disk space: {e}")
            return True  # Assume OK if we can't check
    
    def get_prune_aggression(self) -> int:
        """Get the current cache pruning aggression level."""
        return self.prune_aggression
    
    def cycle_lru_cache_table(self):
        """Cycle the LRU cache table to manage memory usage."""
        # This function is called every 10 seconds. Clearing 17 of the shorts for each call 
        # means that each element will live up to a week (since 1048576 / (8640 * 7) is roughly 17).
        if self.lru_cache_table is None:
            return
            
        clear_until = min(self.LRU_CACHE_SIZE, self.lru_clear_pointer + 17)
        
        # Out.debug(f"CacheHandler: Clearing lruCacheTable from {self.lru_clear_pointer} to {clear_until}")
        
        while self.lru_clear_pointer < clear_until:
            self.lru_cache_table[self.lru_clear_pointer] = 0
            self.lru_clear_pointer += 1
        
        if clear_until >= self.LRU_CACHE_SIZE:
            self.lru_clear_pointer = 0
    
    def mark_recently_accessed(self, hv_file: HVFile, is_new: bool = False) -> bool:
        """Mark a file as recently accessed for LRU management."""
        # This would update LRU information in a real implementation
        hv_file.last_accessed = time.time()
        return True
    
    def get_file_from_cache(self, file_id: str) -> Optional[HVFile]:
        """Get a file from cache by file ID."""
        # Create HVFile and check if it exists and is valid
        # This is a simplified implementation
        
        if len(file_id) >= 2:
            subdir = file_id[:2]
            file_path = self.cache_dir / subdir / file_id
        else:
            file_path = self.cache_dir / file_id
        
        if file_path.exists():
            return self._get_hv_file_from_file(file_path)
        
        return None
    
    def import_file_to_cache(self, temp_file: Path, hv_file: HVFile) -> bool:
        """Import a file to cache from a temporary location."""
        try:
            target_path = hv_file.get_local_file_ref()
            target_path.parent.mkdir(parents=True, exist_ok=True)
            
            Out.debug(f"CacheHandler: Importing file {hv_file.file_id} from {temp_file} to {target_path}")
            
            if not temp_file.exists():
                Out.warning(f"CacheHandler: Temporary file {temp_file} does not exist")
                return False
            
            if Tools.move_file(temp_file, target_path):
                self._add_file_to_active_cache(hv_file)
                self.mark_recently_accessed(hv_file, True)
                
                # Update static range oldest timestamp
                static_range = hv_file.get_static_range()
                if static_range not in self.static_range_oldest:
                    self.static_range_oldest[static_range] = int(time.time() * 1000)
                
                Out.debug(f"CacheHandler: Successfully imported file {hv_file.file_id} to cache")
                return True
            else:
                Out.warning(f"CacheHandler: Failed to move temp file {temp_file} to {target_path}")
                return False
                
        except Exception as e:
            Out.warning(f"CacheHandler: Failed to import file {hv_file.file_id} to cache: {e}")
        
        return False
    
    def delete_file_from_cache(self, hv_file: HVFile):
        """Delete a file from cache."""
        try:
            file_path = hv_file.get_local_file_ref()
            
            if file_path.exists():
                Tools.safe_delete_file(file_path)
                
                with self.lock:
                    self.cache_count -= 1
                    self.cache_size -= hv_file.size
                
                Out.debug(f"CacheHandler: Deleted cached file {hv_file.file_id}")
        except Exception as e:
            Out.error(f"CacheHandler: Failed to delete cache file: {e}")
    
    def terminate_cache(self):
        """Terminate cache handler and save persistent data."""
        Out.info("CacheHandler: Terminating cache handler...")
        
        # Ensure persistent data is saved
        try:
            self._save_persistent_data()
            Out.info("CacheHandler: Persistent cache data saved successfully")
        except Exception as e:
            Out.error(f"CacheHandler: Failed to save persistent cache data during shutdown: {e}")
    
    def save_cache_state(self):
        """Save current cache state to persistent storage (can be called periodically)."""
        try:
            self._save_persistent_data()
            Out.debug("CacheHandler: Cache state saved to persistent storage")
        except Exception as e:
            Out.debug(f"CacheHandler: Failed to save cache state: {e}")
    
    def process_blacklist(self, deltatime: int):
        """Process blacklisted files (placeholder)."""
        # This would implement blacklist processing in a real implementation
        pass
    
    def is_file_verification_on_cooldown(self) -> bool:
        """Check if file verification is on cooldown."""
        current_time = time.time() * 1000
        return (current_time - self.last_file_verification) < 2000  # 2 second cooldown
    
    def get_cache_count(self) -> int:
        """Get the number of cached files."""
        return self.cache_count
    
    def _load_persistent_data(self) -> bool:
        """Load persistent cache data from disk."""
        info_file = Settings.get_data_dir() / "pcache_info"
        
        if not info_file.exists():
            Out.debug("CacheHandler: Missing pcache_info, forcing rescan")
            return False
        
        success = False
        
        try:
            # Read the info file (text format like Java)
            cache_info = info_file.read_text().strip().split('\n')
            info_checksum = 0
            ages_hash = None
            lru_hash = None
            
            for line in cache_info:
                if '=' not in line:
                    continue
                key, value = line.split('=', 1)
                
                if key == 'cacheCount':
                    self.cache_count = int(value)
                    Out.debug(f"CacheHandler: Loaded persistent cacheCount={self.cache_count}")
                    info_checksum |= 1
                elif key == 'cacheSize':
                    self.cache_size = int(value)
                    Out.debug(f"CacheHandler: Loaded persistent cacheSize={self.cache_size}")
                    info_checksum |= 2
                elif key == 'lruClearPointer':
                    self.lru_clear_pointer = int(value)
                    Out.debug(f"CacheHandler: Loaded persistent lruClearPointer={self.lru_clear_pointer}")
                    info_checksum |= 4
                elif key == 'agesHash':
                    ages_hash = value
                    Out.debug(f"CacheHandler: Found agesHash={ages_hash}")
                    info_checksum |= 8
                elif key == 'lruHash':
                    lru_hash = value
                    Out.debug(f"CacheHandler: Found lruHash={lru_hash}")
                    info_checksum |= 16
            
            # Delete info file early like Java (prevents infinite loops on corruption)
            if info_file.exists():
                info_file.unlink()
            
            if info_checksum != 31:  # All 5 flags must be set (1|2|4|8|16 = 31)
                Out.info("CacheHandler: Persistent fields were missing, forcing rescan")
            else:
                Out.info("CacheHandler: All persistent fields found, loading remaining objects")
                
                # Load static range ages
                self.static_range_oldest = self._read_cache_object(
                    Settings.get_data_dir() / "pcache_ages", ages_hash
                )
                
                if len(self.static_range_oldest) > Settings.get_static_range_count():
                    Out.info("CacheHandler: The count of cached static range ages is higher than the current static range count; forcing rescan to prevent orphaned ranges")
                else:
                    Out.info("CacheHandler: Loaded static range ages")
                    
                    # Load LRU cache table (as list in Python, since we don't have fixed-size arrays)
                    self.lru_cache_table = self._read_cache_object(
                        Settings.get_data_dir() / "pcache_lru", lru_hash
                    )
                    Out.info("CacheHandler: Loaded LRU cache")
                    
                    success = True
                    
        except Exception as e:
            Out.debug(f"CacheHandler: Error loading persistent data: {e}")
        
        return success
    
    def _save_persistent_data(self):
        """Save persistent cache data to disk."""
        if not self.cache_loaded:
            return
        
        try:
            # Save static range ages and LRU cache table to separate files with hash validation
            ages_hash = self._write_cache_object(
                Settings.get_data_dir() / "pcache_ages", 
                self.static_range_oldest
            )
            
            lru_hash = self._write_cache_object(
                Settings.get_data_dir() / "pcache_lru", 
                self.lru_cache_table if self.lru_cache_table is not None else [0] * self.LRU_CACHE_SIZE
            )
            
            # Write info file in text format like Java
            info_content = (
                f"cacheCount={self.cache_count}\n"
                f"cacheSize={self.cache_size}\n" 
                f"lruClearPointer={self.lru_clear_pointer}\n"
                f"agesHash={ages_hash}\n"
                f"lruHash={lru_hash}"
            )
            
            info_file = Settings.get_data_dir() / "pcache_info"
            info_file.write_text(info_content)
            
            Out.debug(f"CacheHandler: Saved persistent data - count: {self.cache_count}, size: {Tools.format_bytes(self.cache_size)}")
            
        except Exception as e:
            Out.error(f"CacheHandler: Failed to save persistent cache data: {e}")
            Out.debug(f"CacheHandler: Current state - count: {self.cache_count}, size: {self.cache_size}")
            # Don't re-raise the exception - this shouldn't stop the client
    
    def _delete_persistent_data(self):
        """Delete persistent cache data files."""
        try:
            data_dir = Settings.get_data_dir()
            
            # Delete all three persistent cache files like Java
            info_file = data_dir / "pcache_info"
            ages_file = data_dir / "pcache_ages"
            lru_file = data_dir / "pcache_lru"
            
            if info_file.exists():
                info_file.unlink()
            if ages_file.exists():
                ages_file.unlink()
            if lru_file.exists():
                lru_file.unlink()
                
        except Exception as e:
            Out.debug(f"Failed to delete persistent cache data: {e}")
    
    def _read_cache_object(self, file_path: Path, expected_hash: str):
        """Read and validate a cache object file (equivalent to Java readCacheObject)."""
        if not file_path.exists():
            Out.warning(f"CacheHandler: Missing {file_path}, forcing rescan")
            raise IOError("Missing file")
        
        # Validate file hash
        actual_hash = Tools.get_file_sha1(file_path)
        if actual_hash != expected_hash:
            Out.warning(f"CacheHandler: Incorrect file hash while reading {file_path}, forcing rescan")
            raise IOError("Incorrect file hash")
        
        # Read the pickled object
        with open(file_path, 'rb') as f:
            return pickle.load(f)
    
    def _write_cache_object(self, file_path: Path, obj) -> str:
        """Write a cache object to file and return its SHA1 hash (equivalent to Java writeCacheObject)."""
        Out.debug(f"Writing cache object {file_path}")
        
        # Ensure directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write object to file
        with open(file_path, 'wb') as f:
            pickle.dump(obj, f)
        
        # Calculate and return hash
        file_hash = Tools.get_file_sha1(file_path)
        file_size = file_path.stat().st_size
        Out.debug(f"Wrote cache object {file_path} with size={file_size} hash={file_hash}")
        
        return file_hash
