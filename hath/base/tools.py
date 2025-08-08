"""
Utility tools and helper functions for Hentai@Home Python Client.
"""

import hashlib
import os
import re
import time
from pathlib import Path
from typing import List, Optional, Union


class Tools:
    """Utility functions and tools."""
    
    @staticmethod
    def get_sha1_string(data: Union[str, bytes]) -> str:
        """Calculate SHA1 hash of string or bytes."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha1(data).hexdigest()
    
    @staticmethod
    def parse_additional(additional: str) -> dict:
        """Parse additional parameter string into key-value dictionary.
        
        Java: parseAdditional(String additional)
        Format: key1=value1;key2=value2;...
        """
        add_table = {}
        
        if additional:
            if additional.strip():
                key_value_pairs = additional.strip().split(';')
                
                for kv_pair in key_value_pairs:
                    # Java: if(kvPair.length() > 2)
                    if len(kv_pair) > 2:
                        kv_pair_parts = kv_pair.strip().split('=', 2)
                        
                        if len(kv_pair_parts) == 2:
                            add_table[kv_pair_parts[0].strip()] = kv_pair_parts[1].strip()
                        else:
                            from .out import Out
                            Out.warning(f"Invalid kvPair: {kv_pair}")
                    elif '=' in kv_pair:
                        # Handle edge cases like "a=" or "=b"
                        kv_pair_parts = kv_pair.strip().split('=', 2)
                        if len(kv_pair_parts) == 2:
                            add_table[kv_pair_parts[0].strip()] = kv_pair_parts[1].strip()
        
        return add_table
    
    @staticmethod
    def get_file_sha1(file_path: Path) -> Optional[str]:
        """Calculate SHA1 hash of a file."""
        try:
            sha1_hash = hashlib.sha1()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha1_hash.update(chunk)
            return sha1_hash.hexdigest()
        except Exception:
            return None
    
    @staticmethod
    def get_string_file_contents(file_path: Path) -> str:
        """Read the entire contents of a file as a string."""
        try:
            return file_path.read_text(encoding='utf-8')
        except Exception:
            return ""
    
    @staticmethod
    def list_sorted_files(directory: Path) -> List[Path]:
        """List files in a directory, sorted by name."""
        try:
            if not directory.exists() or not directory.is_dir():
                return []
            return sorted([f for f in directory.iterdir() if f.is_file()])
        except Exception:
            return []
    
    @staticmethod
    def list_sorted_dirs(directory: Path) -> List[Path]:
        """List subdirectories in a directory, sorted by name."""
        try:
            if not directory.exists() or not directory.is_dir():
                return []
            return sorted([d for d in directory.iterdir() if d.is_dir()])
        except Exception:
            return []
    
    @staticmethod
    def is_valid_filename(filename: str) -> bool:
        """Check if a filename is valid."""
        if not filename or len(filename) > 255:
            return False
        
        # Check for invalid characters
        invalid_chars = r'[<>:"/\\|?*\x00-\x1f]'
        if re.search(invalid_chars, filename):
            return False
        
        # Check for reserved names (Windows)
        reserved_names = {
            'CON', 'PRN', 'AUX', 'NUL',
            'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
            'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
        }
        name_upper = filename.upper()
        if name_upper in reserved_names or name_upper.split('.')[0] in reserved_names:
            return False
        
        return True
    
    @staticmethod
    def get_free_disk_space(path: Path) -> int:
        """Get free disk space in bytes for the given path."""
        try:
            stat = os.statvfs(str(path))
            return stat.f_bavail * stat.f_frsize
        except (AttributeError, OSError):
            # Fallback for Windows
            try:
                import shutil
                return shutil.disk_usage(str(path)).free
            except Exception:
                return 0
    
    @staticmethod
    def get_current_time_millis() -> int:
        """Get current time in milliseconds."""
        return int(time.time() * 1000)
    
    @staticmethod
    def format_bytes(bytes_value: int) -> str:
        """Format bytes into human readable format."""
        value = float(bytes_value)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if value < 1024.0:
                return f"{value:.2f} {unit}"
            value /= 1024.0
        return f"{value:.2f} PB"
    
    @staticmethod
    def create_directory_if_not_exists(path: Path) -> bool:
        """Create directory if it doesn't exist."""
        try:
            path.mkdir(parents=True, exist_ok=True)
            return True
        except Exception:
            return False
    
    @staticmethod
    def move_file(src: Path, dst: Path) -> bool:
        """Move a file from source to destination."""
        try:
            # Ensure destination directory exists
            dst.parent.mkdir(parents=True, exist_ok=True)
            src.rename(dst)
            return True
        except Exception:
            return False
    
    @staticmethod
    def safe_delete_file(file_path: Path) -> bool:
        """Safely delete a file."""
        try:
            if file_path.exists() and file_path.is_file():
                file_path.unlink()
                return True
            return False
        except Exception:
            return False
    
    @staticmethod
    def get_file_size(file_path: Path) -> int:
        """Get file size in bytes."""
        try:
            return file_path.stat().st_size
        except Exception:
            return 0
