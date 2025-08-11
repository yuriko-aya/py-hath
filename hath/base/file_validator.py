"""
File validator for checking file integrity and corruption.

This module provides file validation using SHA1 hashes to detect
file corruption and ensure data integrity.
"""

import hashlib
import threading
import time
from pathlib import Path
from typing import Optional, Dict, Set
from .out import Out


class FileValidator:
    """Validates file integrity using SHA1 hashes."""
    
    _instance = None
    _instance_lock = threading.RLock()
    
    def __new__(cls, *args, **kwargs):
        """Ensure singleton pattern."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    def get_instance(cls):
        """Get the singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def __init__(self):
        """Initialize the file validator."""
        # Prevent multiple initialization
        if hasattr(self, '_initialized'):
            return
        
        self._validation_cache: Dict[str, float] = {}  # file_id -> last_validation_time
        self._validation_lock = threading.RLock()
        self._last_validation_time = 0
        
        # Validation frequency limits (from Java implementation)
        self._min_validation_interval = 7 * 24 * 3600  # 1 week minimum between validations
        self._min_time_between_validations = 2  # 2 seconds minimum between any validations
        
        self._initialized = True
    
    def validate_file(self, file_path: Path, expected_hash: str, file_id: str = None, 
                     force: bool = False) -> bool:
        """Validate a file's SHA1 hash.
        
        Args:
            file_path: Path to the file to validate
            expected_hash: Expected SHA1 hash (lowercase hex)
            file_id: Optional file ID for validation frequency tracking
            force: Force validation even if recently validated
            
        Returns:
            True if file is valid, False if corrupted or missing
        """
        if not file_path.exists():
            Out.debug(f"File validation failed: {file_path} does not exist")
            return False
        
        # Check if we should skip validation due to frequency limits
        if not force and file_id and not self._should_validate_file(file_id):
            Out.debug(f"Skipping validation for {file_id} (recently validated)")
            return True
        
        try:
            # Calculate actual hash
            actual_hash = self._calculate_sha1(file_path)
            
            if actual_hash.lower() == expected_hash.lower():
                Out.debug(f"File validation successful: {file_path}")
                
                # Record successful validation
                if file_id:
                    self._record_validation(file_id)
                
                return True
            else:
                Out.warning(f"File validation failed: {file_path}")
                Out.warning(f"Expected: {expected_hash}")
                Out.warning(f"Actual:   {actual_hash}")
                return False
        
        except Exception as e:
            Out.error(f"Error validating file {file_path}: {e}")
            return False
    
    def validate_file_during_serving(self, file_path: Path, expected_hash: str, 
                                   file_id: str, chunk_processor: Optional[callable] = None) -> bool:
        """Validate a file while reading it (for serving).
        
        This method allows validation during file serving to avoid
        additional I/O overhead, similar to the Java implementation.
        
        Args:
            file_path: Path to the file to validate
            expected_hash: Expected SHA1 hash
            file_id: File ID for tracking
            chunk_processor: Optional function to process chunks during reading
            
        Returns:
            True if file is valid
        """
        if not file_path.exists():
            return False
        
        # Check if we should validate this file
        if not self._should_validate_file(file_id):
            return True  # Assume valid if we're not due for validation
        
        try:
            sha1_hash = hashlib.sha1()
            bytes_read = 0
            
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    
                    # Update hash
                    sha1_hash.update(chunk)
                    bytes_read += len(chunk)
                    
                    # Process chunk if callback provided
                    if chunk_processor:
                        chunk_processor(chunk)
            
            actual_hash = sha1_hash.hexdigest()
            
            if actual_hash.lower() == expected_hash.lower():
                Out.debug(f"Inline validation successful for {file_id}")
                self._record_validation(file_id)
                return True
            else:
                Out.warning(f"Inline validation failed for {file_id}")
                Out.warning(f"Expected: {expected_hash}, Actual: {actual_hash}")
                return False
        
        except Exception as e:
            Out.error(f"Error during inline validation of {file_id}: {e}")
            return False
    
    def _should_validate_file(self, file_id: str) -> bool:
        """Check if a file should be validated based on frequency limits.
        
        Args:
            file_id: File ID to check
            
        Returns:
            True if file should be validated
        """
        with self._validation_lock:
            current_time = time.time()
            
            # Check minimum time between any validations
            if current_time - self._last_validation_time < self._min_time_between_validations:
                return False
            
            # Check if this specific file was validated recently
            last_validation = self._validation_cache.get(file_id, 0)
            if current_time - last_validation < self._min_validation_interval:
                return False
            
            return True
    
    def _record_validation(self, file_id: str):
        """Record that a file was validated.
        
        Args:
            file_id: File ID that was validated
        """
        with self._validation_lock:
            current_time = time.time()
            self._validation_cache[file_id] = current_time
            self._last_validation_time = current_time
            
            # Clean up old entries (keep only last 1000 entries)
            if len(self._validation_cache) > 1000:
                # Remove oldest entries
                sorted_items = sorted(self._validation_cache.items(), key=lambda x: x[1])
                items_to_keep = sorted_items[-500:]  # Keep newest 500
                self._validation_cache = dict(items_to_keep)
    
    def _calculate_sha1(self, file_path: Path) -> str:
        """Calculate SHA1 hash of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            SHA1 hash as lowercase hex string
        """
        sha1_hash = hashlib.sha1()
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha1_hash.update(chunk)
        
        return sha1_hash.hexdigest()
    
    def validate_data(self, data: bytes, expected_hash: str) -> bool:
        """Validate data in memory.
        
        Args:
            data: Data to validate
            expected_hash: Expected SHA1 hash
            
        Returns:
            True if data is valid
        """
        actual_hash = hashlib.sha1(data).hexdigest()
        return actual_hash.lower() == expected_hash.lower()
    
    def calculate_hash(self, file_path: Path) -> Optional[str]:
        """Calculate SHA1 hash of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            SHA1 hash as lowercase hex string, or None if error
        """
        try:
            return self._calculate_sha1(file_path)
        except Exception as e:
            Out.error(f"Error calculating hash for {file_path}: {e}")
            return None
    
    def get_validation_stats(self) -> Dict[str, int]:
        """Get validation statistics.
        
        Returns:
            Dictionary with validation statistics
        """
        with self._validation_lock:
            current_time = time.time()
            
            # Count validations in different time periods
            recent_validations = 0  # Last hour
            daily_validations = 0   # Last 24 hours
            
            for validation_time in self._validation_cache.values():
                if current_time - validation_time < 3600:  # 1 hour
                    recent_validations += 1
                if current_time - validation_time < 86400:  # 24 hours
                    daily_validations += 1
            
            return {
                'total_files_tracked': len(self._validation_cache),
                'validations_last_hour': recent_validations,
                'validations_last_24h': daily_validations,
                'last_validation_time': int(self._last_validation_time)
            }
    
    def clear_validation_cache(self):
        """Clear the validation cache."""
        with self._validation_lock:
            self._validation_cache.clear()
            Out.debug("File validation cache cleared")


# Global file validator instance
_file_validator: Optional[FileValidator] = None
_validator_lock = threading.Lock()


def get_file_validator() -> FileValidator:
    """Get the global file validator instance.
    
    Returns:
        Global FileValidator instance
    """
    global _file_validator
    
    if _file_validator is None:
        with _validator_lock:
            if _file_validator is None:
                _file_validator = FileValidator()
    
    return _file_validator


def validate_file(file_path: Path, expected_hash: str, file_id: str = None) -> bool:
    """Convenience function to validate a file.
    
    Args:
        file_path: Path to the file to validate
        expected_hash: Expected SHA1 hash
        file_id: Optional file ID for frequency tracking
        
    Returns:
        True if file is valid
    """
    validator = get_file_validator()
    return validator.validate_file(file_path, expected_hash, file_id)
