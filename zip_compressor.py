"""
ZIP Compressor for Hentai@Home Python Client

This standalone script is responsible for compressing individual downloaded gallery
directories into ZIP archives and cleaning up the original directories. It's designed
to run as a separate process to avoid blocking the main download manager.

The script processes a single gallery directory and:
- Creates a ZIP file with the same name as the directory
- Compresses all files within the directory recursively  
- Removes the original directory after successful compression
- Logs all operations for debugging and monitoring
- Skips compression if ZIP file already exists and is non-empty

Usage:
    python zip_compressor.py <gallery_directory_path>
    
Example:
    python zip_compressor.py "/downloads/Gallery Title [12345-1280x]"
    
Features:
- Uses ZIP_DEFLATED compression for optimal file size
- Maintains directory structure within ZIP files
- Comprehensive error handling and logging
- Safe cleanup only after successful compression
- Duplicate prevention by checking existing ZIP files

Author: H@H Python Client
Version: 0.2
"""

import logging
import zipfile
import log_manager
import sys
import shutil

from pathlib import Path

logger = logging.getLogger('zip_compressor')

log_manager.setup_file_logging()

data_dir = sys.argv[1] if len(sys.argv) > 1 else None
if data_dir is None:
    logger.error("Data directory argument is required")
    sys.exit(1)

dir_path = Path(data_dir)
if not dir_path.exists() or not dir_path.is_dir():
    logger.error(f"Provided path is not a valid directory: {data_dir}")
    sys.exit(1)

zip_file = dir_path.with_name(dir_path.name + ".zip")
if zip_file.exists() and zip_file.stat().st_size > 0:
    logger.info(f"ZIP file already exists and is non-empty, skipping: {zip_file.name}")
    sys.exit(0)

try:
    logger.info(f"Creating zip for {dir_path.name}")
    with zipfile.ZipFile(zip_file, "w", zipfile.ZIP_DEFLATED) as zipf:
        for file in dir_path.rglob("*"):
            if file.is_file():
                zipf.write(file, file.relative_to(dir_path))
    # Delete directory after successful zip
    shutil.rmtree(dir_path)
    logger.info(f"Successfully zipped and deleted {dir_path.name}")
except Exception as e:
    logger.error(f"Failed to zip {dir_path}: {e}")
    if zip_file.exists():
        try:
            zip_file.unlink()
            logger.info(f"Deleted incomplete zip file: {zip_file.name}")
        except Exception as del_err:
            logger.error(f"Error deleting incomplete zip file: {del_err}")

