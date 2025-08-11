"""
Simple file downloader utility for small files.

This module provides a simple HTTP download function for
metadata and other small files.
"""

import socket
import ssl
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

from .out import Out


def download_file_simple(url: str, output_path: Path, timeout: int = 30) -> bool:
    """Download a file with a simple HTTP request.
    
    Args:
        url: URL to download
        output_path: Path to save file
        timeout: Download timeout in seconds
        
    Returns:
        True if successful
    """
    try:
        # Create SSL context with minimal security for old servers
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Create opener with timeout
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_context))
        
        # Set headers
        request = urllib.request.Request(url)
        request.add_header('User-Agent', 'Mozilla/5.0 (compatible; HentaiAtHome)')
        
        # Download with timeout
        with opener.open(request, timeout=timeout) as response:
            if response.getcode() != 200:
                Out.warning(f"Download failed: HTTP {response.getcode()}")
                return False
            
            # Read response
            data = response.read()
            
            # Write to file
            output_path.write_bytes(data)
            
        return True
        
    except (urllib.error.URLError, socket.timeout) as e:
        Out.warning(f"Download failed: {e}")
        return False
    except Exception as e:
        Out.warning(f"Unexpected download error: {e}")
        return False
