"""
Cache handler for managing local file cache.
"""

import os
import pickle
import re
import shutil
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Set

try:
    import javaobj
    JAVAOBJ_AVAILABLE = True
except ImportError:
    javaobj = None
    JAVAOBJ_AVAILABLE = False

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
        # Files are stored in subdirectories based on first 2 characters of file_id (static range)
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
    
    def getSize(self) -> int:
        """Get the size of the file (Java compatibility method)."""
        return self.size
    
    def getHash(self) -> str:
        """Get the SHA1 hash of the file (Java compatibility method)."""
        return self.sha1_hash
    
    @property
    def hash(self) -> str:
        """Get the SHA1 hash of the file (property for compatibility)."""
        return self.sha1_hash

    @staticmethod
    def getHVFileFromFileid(file_id: str) -> Optional['HVFile']:
        """Create an HVFile instance from a file ID string.
        
        Args:
            file_id: File ID in format "hash-size-type" or "hash-size-xres-yres-type"
            
        Returns:
            HVFile instance or None if invalid format
        """
        if not HVFile.is_valid_hv_fileid(file_id):
            Out.warning(f"Invalid fileid \"{file_id}\"")
            return None
            
        try:
            parts = file_id.split('-')
            hash_part = parts[0]
            size = int(parts[1])
            
            # Extract just the hash from the full file_id for validation
            sha1_hash = hash_part
            
            return HVFile(file_id, size, sha1_hash)
        except Exception as e:
            Out.warning(f"Failed to parse fileid \"{file_id}\": {e}")
            return None
    
    @staticmethod 
    def is_valid_hv_fileid(file_id: str) -> bool:
        """Check if a file ID has valid format.
        
        Args:
            file_id: File ID to validate
            
        Returns:
            True if valid, False otherwise
        """
        # Pattern for hash-size-xres-yres-type format
        pattern1 = r'^[a-f0-9]{40}-[0-9]{1,10}-[0-9]{1,5}-[0-9]{1,5}-(jpg|png|gif|mp4|wbm|wbp|avf|jxl)$'
        
        # Pattern for hash-size-type format (no resolution)
        pattern2 = r'^[a-f0-9]{40}-[0-9]{1,10}-(jpg|png|gif|mp4|wbm|wbp|avf|jxl)$'
        
        return bool(re.match(pattern1, file_id) or re.match(pattern2, file_id))


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
            try:
                if self._load_persistent_data():
                    Out.info("CacheHandler: Successfully loaded persistent cache data")
                    fast_startup = True
                else:
                    Out.info("CacheHandler: Persistent cache data is not available")
            except RuntimeError as e:
                # Fatal error loading cache data - this should trigger shutdown
                Out.error("CacheHandler: Fatal error during cache initialization!")
                raise e  # Re-raise to trigger shutdown
        
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
                files = Tools.list_sorted_files(cache_dir)
                actual_file_count += len([f for f in files if f.is_file() and Settings.is_static_range(f.name)])
            
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
            
            # Loop the directory, check if file is in a valid static range
            files = Tools.list_sorted_files(l1_dir)
            for file in files:
                if not Settings.is_static_range(file.name):
                    Out.debug(f"CacheHandler: Removing invalid static range file {file}")
                    Tools.safe_delete_file(file)
            
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
                if not Settings.is_static_range(file_path.name):
                    continue

                if not file_path.is_file():
                    continue
                
                hv_file = self._get_hv_file_from_file(file_path)
                
                if hv_file is None:
                    Out.debug(f"CacheHandler: The file {file_path} was corrupt.")
                    Tools.safe_delete_file(file_path)
                else:
                    # File is valid and we already verified the directory represents a valid static range
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
            for file_path in Tools.list_sorted_files(cache_dir):
                if not Settings.is_static_range(file_path.name):
                    continue
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
        
        # Ensure the LRU cache table has the expected size
        if len(self.lru_cache_table) != self.LRU_CACHE_SIZE:
            Out.warning(f"CacheHandler: LRU cache table size mismatch: {len(self.lru_cache_table)} != {self.LRU_CACHE_SIZE}, reinitializing")
            self.lru_cache_table = [0] * self.LRU_CACHE_SIZE
            self.lru_clear_pointer = 0
        
        # Ensure lru_clear_pointer is within bounds
        if self.lru_clear_pointer >= len(self.lru_cache_table):
            Out.warning(f"CacheHandler: LRU clear pointer out of bounds: {self.lru_clear_pointer} >= {len(self.lru_cache_table)}, resetting")
            self.lru_clear_pointer = 0
            
        clear_until = min(self.LRU_CACHE_SIZE, self.lru_clear_pointer + 17)
        
        # Out.debug(f"CacheHandler: Clearing lruCacheTable from {self.lru_clear_pointer} to {clear_until}")
        
        while self.lru_clear_pointer < clear_until:
            if self.lru_clear_pointer < len(self.lru_cache_table):
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
        """Process blacklisted files by removing them from cache.
        
        Args:
            deltatime: Time elapsed since last processing (in milliseconds)
        """
        # In a full implementation, this would:
        # 1. Check for files that have been marked as blacklisted by the server
        # 2. Remove them from the local cache
        # 3. Update internal cache tracking structures
        
        # For now, implement basic cleanup of invalid files
        try:
            removed_count = 0
            removed_size = 0
            
            # Process cache directories to find invalid files
            for cache_dir in Tools.list_sorted_dirs(self.cache_dir):
                # Check files in valid static range directories
                for file_path in Tools.list_sorted_files(cache_dir):
                    if not file_path.is_file():
                        continue
                    
                    # Get HVFile for validation
                    hv_file = self._get_hv_file_from_file(file_path)
                    
                    # Remove invalid files (this acts as a basic blacklist cleanup)
                    if hv_file is None or not hv_file.is_valid() or not Settings.is_static_range(file_path.name):
                        try:
                            file_size = Tools.get_file_size(file_path)
                            Tools.safe_delete_file(file_path)
                            
                            with self.lock:
                                self.cache_count -= 1
                                self.cache_size -= file_size
                            
                            removed_count += 1
                            removed_size += file_size
                            
                            Out.debug(f"CacheHandler: Removed invalid/blacklisted file: {file_path.name}")
                            
                        except Exception as e:
                            Out.warning(f"CacheHandler: Failed to remove invalid file {file_path}: {e}")
            
            if removed_count > 0:
                Out.info(f"CacheHandler: Blacklist processing removed {removed_count} files ({Tools.format_bytes(removed_size)})")
                
        except Exception as e:
            Out.error(f"CacheHandler: Error during blacklist processing: {e}")
    
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
                    loaded_pointer = int(value)
                    # Validate the loaded pointer is within bounds
                    if 0 <= loaded_pointer < self.LRU_CACHE_SIZE:
                        self.lru_clear_pointer = loaded_pointer
                    else:
                        Out.warning(f"CacheHandler: Loaded lruClearPointer {loaded_pointer} is out of bounds, using 0")
                        self.lru_clear_pointer = 0
                    Out.debug(f"CacheHandler: Set lruClearPointer={self.lru_clear_pointer}")
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
                
                # Ensure hashes are not None
                if ages_hash is None or lru_hash is None:
                    Out.warning("CacheHandler: Missing hash values, forcing rescan")
                    return False
                
                # Load static range ages
                ages_data = self._read_cache_object(
                    Settings.get_data_dir() / "pcache_ages", ages_hash
                )
                if isinstance(ages_data, dict):
                    self.static_range_oldest = ages_data
                    
                    # Convert 4-character Java cache static ranges to 2-character ranges for Settings
                    # This ensures that files from Java cache aren't marked as invalid
                    if ages_data and not Settings._static_ranges:
                        Out.debug("CacheHandler: Converting Java cache 4-char static ranges to 2-char ranges for Settings")
                        derived_ranges = {}
                        for java_range in ages_data.keys():
                            if len(java_range) >= 2:
                                two_char_range = java_range[:2]
                                derived_ranges[two_char_range] = 1
                        
                        if derived_ranges:
                            Settings._static_ranges = derived_ranges
                            Settings._current_static_range_count = len(derived_ranges)
                            Out.debug(f"CacheHandler: Derived {len(derived_ranges)} 2-char static ranges: {list(derived_ranges.keys())}")
                    
                else:
                    Out.warning("CacheHandler: Ages data is not a dict, forcing rescan")
                    return False
                
                if len(self.static_range_oldest) > Settings.get_static_range_count():
                    Out.info("CacheHandler: The count of cached static range ages is higher than the current static range count; forcing rescan to prevent orphaned ranges")
                else:
                    Out.info("CacheHandler: Loaded static range ages")
                    
                    # Load LRU cache table (as list in Python, since we don't have fixed-size arrays)
                    lru_data = self._read_cache_object(
                        Settings.get_data_dir() / "pcache_lru", lru_hash
                    )
                    if isinstance(lru_data, list):
                        # Ensure LRU data has the correct size
                        if len(lru_data) == self.LRU_CACHE_SIZE:
                            self.lru_cache_table = lru_data
                        else:
                            Out.warning(f"CacheHandler: LRU data size mismatch: {len(lru_data)} != {self.LRU_CACHE_SIZE}, creating new table")
                            self.lru_cache_table = [0] * self.LRU_CACHE_SIZE
                    else:
                        Out.warning("CacheHandler: LRU data is not a list, forcing rescan")
                        return False
                    Out.info("CacheHandler: Loaded LRU cache")
                    
                    success = True
                    
        except RuntimeError as e:
            # Fatal error - cannot continue with incompatible cache data
            Out.error(f"CacheHandler: Fatal error loading persistent cache data: {e}")
            Out.error("CacheHandler: This is a critical error that requires immediate shutdown.")
            Out.error("CacheHandler: Please either:")
            Out.error("  1. Install required dependencies (javaobj-py3) to read Java cache data")
            Out.error("  2. Delete the cache data files and restart with a clean cache")
            Out.error("  3. Use the --rescan-cache option to force cache rebuild")
            
            # Re-raise as a fatal error
            raise RuntimeError(f"Cannot load persistent cache data: {e}")
            
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
        
        # Check if it's Java serialization format (starts with 0xaced0005)
        with open(file_path, 'rb') as f:
            magic = f.read(4)
            f.seek(0)
            
            if magic == b'\xac\xed\x00\x05':
                # Java serialized data
                if not JAVAOBJ_AVAILABLE:
                    Out.error("CacheHandler: Found Java serialized cache data but javaobj library is not available!")
                    Out.error("CacheHandler: Please install javaobj-py3: pip install javaobj-py3")
                    Out.error("CacheHandler: Cannot continue with incompatible cache data format.")
                    raise RuntimeError("Java serialized cache data requires javaobj-py3 library")
                
                try:
                    Out.debug(f"CacheHandler: Reading Java serialized object from {file_path}")
                    java_obj = javaobj.load(f)  # type: ignore
                    
                    # Convert Java Hashtable to Python dict
                    if hasattr(java_obj, 'annotations') and java_obj.classdesc.name == 'java.util.Hashtable':
                        # Java Hashtable data is stored in annotations as alternating key-value pairs
                        annotations = java_obj.annotations
                        # Skip the first element (binary data) and process pairs starting from index 1
                        data = {}
                        i = 1  # Start after binary data
                        while i + 1 < len(annotations):
                            key = str(annotations[i])
                            value = int(annotations[i + 1])
                            data[key] = value
                            i += 2
                        Out.debug(f"CacheHandler: Converted Java Hashtable with {len(data)} entries")
                        return data
                    elif hasattr(java_obj, 'annotations') and '[S' in str(java_obj.classdesc.name):
                        # Java short array - convert to Python list
                        Out.debug(f"CacheHandler: Converting Java short array with {len(java_obj.annotations)} elements")
                        return list(java_obj.annotations)
                    else:
                        Out.error(f"CacheHandler: Unknown Java object type: {java_obj.classdesc.name}")
                        Out.error("CacheHandler: Cannot continue with unknown cache data format.")
                        raise RuntimeError(f"Unknown Java object type: {java_obj.classdesc.name}")
                        
                except Exception as e:
                    Out.error(f"CacheHandler: Failed to read Java serialized cache data: {e}")
                    Out.error("CacheHandler: Cache data is corrupted or incompatible.")
                    raise RuntimeError(f"Failed to read Java cache data: {e}")
            else:
                # Python pickle format
                try:
                    f.seek(0)
                    return pickle.load(f)
                except Exception as e:
                    Out.error(f"CacheHandler: Failed to read Python pickle cache data: {e}")
                    Out.error("CacheHandler: Cache data is corrupted.")
                    raise RuntimeError(f"Failed to read Python cache data: {e}")
    
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
        if file_hash is None:
            raise RuntimeError(f"Failed to calculate hash for {file_path}")
        
        file_size = file_path.stat().st_size
        Out.debug(f"Wrote cache object {file_path} with size={file_size} hash={file_hash}")
        
        return file_hash
