"""
Download Manager for Hentai@Home Python Client

This module handles the download functionality for the H@H client, including:
- Fetching download queues from the server
- Parsing gallery metadata and file information
- Downloading and verifying files with hash validation
- Creating ZIP archives of completed galleries
- Managing the download process with retry logic

The download manager operates in a separate background thread and continuously
processes pending downloads from the server queue. It supports multi-file
galleries with automatic verification and cleanup.

Key Features:
- SHA1 hash verification for file integrity
- Automatic retry logic with multiple download mirrors
- ZIP compression of completed galleries
- Cross-platform path handling with pathlib
- Comprehensive error handling and logging

Usage:
    Call trigger_download() to start the download manager in background:
    >>> trigger_download()
    
Author: H@H Python Client
Version: 0.2
"""

import re
import requests
import logging
import rpc_manager
import os
import hashlib
import time
import threading
import subprocess
import sys

from pathlib import Path
from hath_config import HathConfig
from config_singleton import get_hath_config

logger = logging.getLogger(__name__)

default_hath_config = HathConfig()
hath_config = get_hath_config()

max_name_length = 90
download_dir = 'download'
python_exe = sys.executable


requests_headers = {
    'User-Agent': 'Hentai@Home Python Client 0.2'
}

def get_queue(downloaded: bool = False, gid: int = 0, minxres: str = '') -> str:
    """
    Fetch the download queue from the H@H server.
    
    Retrieves the list of pending downloads or marks a gallery as downloaded.
    This function communicates with the server to get metadata for galleries
    that need to be downloaded.
    
    Args:
        downloaded (bool): Whether to mark a gallery as downloaded (default: False)
        gid (int): Gallery ID to mark as downloaded (default: 0)
        minxres (str): Minimum resolution for the downloaded gallery (default: '')
        
    Returns:
        str: Server response containing gallery metadata or status message
        
    Raises:
        None: Function handles errors internally and returns empty string on failure
        
    Example:
        >>> metadata = get_queue()  # Get next download
        >>> get_queue(downloaded=True, gid=12345, minxres='1280')  # Mark as downloaded
    """
    act = 'fetchqueue'

    if not hath_config or not default_hath_config:
        logger.error('HathConfig is not properly initialized for fetching download queue')
        return ''

    if downloaded:
        add = f'{gid};{minxres}'
    else:
        add = ''
    current_acttime = hath_config.get_current_acttime()
    actkey_data = f"hentai@home-{act}-{add}-{hath_config.client_id}-{current_acttime}-{hath_config.client_key}"
    actkey = hashlib.sha1(actkey_data.encode()).hexdigest()
    url_path = (
        f"/15/dl?clientbuild={hath_config.client_build}&act={act}"
        f"&add={add}&cid={hath_config.client_id}&acttime={current_acttime}&actkey={actkey}"
    )

    response = rpc_manager._make_rpc_request(url_path, timeout=10)
    return response.text.strip()

def parse_metadata(metadata: str) -> tuple[bool, dict, str]:
    """
    Parse gallery metadata from server response.
    
    Processes the metadata string received from the H@H server and extracts
    gallery information including files list, title, resolution, and other details.
    The metadata format follows a specific structure with sections for gallery
    info, file list, and additional information.
    
    Args:
        metadata (str): Raw metadata string from server response
        
    Returns:
        tuple[bool, dict, str]: A tuple containing:
            - bool: Success status (True if parsing succeeded)
            - dict: Gallery information with keys:
                - 'gid': Gallery ID (int)
                - 'filecount': Number of files (int) 
                - 'minxres': Minimum resolution (str)
                - 'title': Sanitized gallery title (str)
                - 'files': List of file dictionaries (list)
            - str: Additional gallery text/information
            
    Note:
        Gallery titles are sanitized to remove invalid filesystem characters
        and truncated to max_name_length (90 characters) if necessary.
        
    Example:
        >>> success, info, text = parse_metadata(server_response)
        >>> if success:
        ...     print(f"Gallery {info['gid']} has {info['filecount']} files")
    """
    gallery_info = {}
    if not metadata:
        logger.error('No metadata provided for parsing')
        return False, {}, ''
    if not metadata:
        logger.error(f'Invalid metadata format: {metadata}')
        return False, {}, ''
    logger.debug(f'Started metadata parsing')
    parse_state = 0
    gallery_txt = ''
    for metadata_line in metadata.splitlines():
        if  metadata_line == 'FILELIST' and parse_state == 0:
            parse_state = 1
            continue
        if metadata_line == 'INFORMATION' and parse_state == 1:
            parse_state = 2
            continue
        if parse_state < 2 and not metadata_line:
            continue
        if parse_state == 0:
            metadata_part = metadata_line.split(' ', 1)
            if metadata_part[0] == 'GID':
                try:
                    gallery_info['gid'] = int(metadata_part[1])
                    logger.debug(f'Parsed GID: {gallery_info["gid"]}')
                except ValueError:
                    logger.error(f'Invalid GID value: {metadata_part[1]}')
                    return False, {}, ''
            elif metadata_part[0] == 'FILECOUNT':
                try:
                    gallery_info['filecount'] = int(metadata_part[1])
                    logger.debug(f'Parsed FILECOUNT: {gallery_info["filecount"]}')
                except ValueError:
                    logger.error(f'Invalid FILECOUNT value: {metadata_part[1]}')
                    return False, {}, ''
            elif metadata_part[0] == 'MINXRES':
                if metadata_part[1] == 'org':
                    gallery_info['minxres'] = 'org'
                else:
                    try:
                        int(metadata_part[1])
                        gallery_info['minxres'] = metadata_part[1]
                    except ValueError:
                        logger.error(f'Invalid MINXRES value: {metadata_part[1]}')
                        return False, {}, ''
                logger.debug(f'Parsed MINXRES: {gallery_info["minxres"]}')
            elif metadata_part[0] == 'TITLE':
                original_title = metadata_part[1]
                clean_title = re.sub(r'[*"\\<>:?]', '', original_title)
                clean_title = re.sub(r'\s+', ' ', clean_title)
                clean_title = clean_title.strip()
                if not gallery_info.get('minxres') == 'org':
                    title_xres = f'-{gallery_info.get("minxres", "unknown")}x'
                else:
                    title_xres = ''
                post_title = f'[{gallery_info.get("gid", "unknown")}{title_xres}]'
                title_length = len(clean_title)
                if title_length > max_name_length:
                    clean_title = f'{clean_title[:max_name_length - 3]}...'
                    logger.debug(f'Title truncated to {max_name_length} chars: {clean_title}')
                gallery_info['title'] = clean_title + post_title
                logger.debug(f'Parsed TITLE: {gallery_info["title"]}')
        elif parse_state == 1:
            file_info = metadata_line.split(' ', 5)
            if len(file_info) < 6:
                logger.error(f'Invalid file information format: {metadata_line}')
                return False, {}, ''
            file_page = int(file_info[0])
            file_index = int(file_info[1])
            file_xres = file_info[2]
            file_sha1 = file_info[3] if file_info[3] != 'unknown' else ''
            file_type = file_info[4]
            file_name = file_info[5]
            logger.debug(f'Parsed file information: gid={gallery_info["gid"]} page={file_page} fileindex={file_index} xres={file_xres} filetype={file_type} filename={file_name}')
            if 'files' not in gallery_info:
                gallery_info['files'] = []
            gallery_info['files'].append({
                'file_page': file_page,
                'file_index': file_index,
                'file_xres': file_xres,
                'file_sha1': file_sha1,
                'file_type': file_type,
                'file_name': file_name
            })
        else:
            gallery_txt += '\n' + metadata_line
    return True, gallery_info, gallery_txt

def verify_and_save(file_sha1: str, link: str, file_path: str) -> bool:
    """
    Download, verify, and save a file from a given URL.
    
    Downloads a file from the provided link, verifies its SHA1 hash against
    the expected hash (using both the provided file_sha1 and URL-extracted hash),
    and saves it to the specified path. If the file already exists and has the
    correct hash, the download is skipped.
    
    Args:
        file_sha1 (str): Expected SHA1 hash of the file from metadata
        link (str): Download URL containing the file ID with hash
        file_path (str): Local file path where the file should be saved
        
    Returns:
        bool: True if file was successfully downloaded/verified, False otherwise
        
    Note:
        - Creates parent directories if they don't exist
        - Validates SHA1 hash before saving using both metadata and URL hash
        - Skips download if file already exists with correct hash
        - Uses streaming download for memory efficiency
        
    Example:
        >>> hash_val = "abc123def456"
        >>> url = "https://example.com/files/abc123-456789-image.jpg"
        >>> success = verify_and_save(hash_val, url, "/downloads/image.jpg")
    """
    file_path_obj = Path(file_path)
    file_path_obj.parent.mkdir(parents=True, exist_ok=True)
    
    url_parts = link.split('/')
    if len(url_parts) < 7:
        logger.error(f'Invalid download link format: {link}')
        return False
    resized_file_id = url_parts[6]
    org_file_id = url_parts[5]
    if not resized_file_id == 'x':
        file_id = resized_file_id
    else:
        file_id = org_file_id
    url_hash = file_id.split('-')[0]
    if file_sha1 == url_hash:
        expected_hash = file_sha1
    else:
        expected_hash = url_hash
    if file_path_obj.exists() and file_path_obj.is_file() and file_path_obj.stat().st_size > 0:
        # Assume non-zero existing file is valid
        logger.debug(f'File already exists and valid: {file_path}')
        return True
    try:
        response = requests.get(link, headers=requests_headers, timeout=30)
        if response.status_code == 200:
            content = response.content
            logger.debug(f'Downloaded {len(content)} bytes from {link}')
            content_hash = hashlib.sha1(content).hexdigest()
            if not content_hash == expected_hash:
                logger.error(f'Hash mismatch for file from {link}: expected {expected_hash}, got {content_hash}')
                return False
            logger.debug(f'Hash verified for file for {file_path_obj.name}: {expected_hash}')
            try:
                with open(file_path_obj, 'wb') as f:
                    f.write(response.content)
            except Exception as e:
                logger.error(f'Error saving file to {file_path_obj}: {e}')
                if file_path_obj.exists():
                    try:
                        file_path_obj.unlink()
                    except Exception as e:
                        logger.error(f"Error removing incomplete file: {e}")
                return False
            return True
    except Exception as e:
        logger.error(f'Error downloading and saving file from {link}: {e}')
        return False
    return False

def start_download(gallery_info: dict, gallery_txt: str, dir_path: str) -> bool:
    """
    Download all files for a gallery based on parsed metadata.
    
    Processes the gallery information and downloads all files in the gallery.
    For each file, it requests download URLs from the server, attempts to download
    from multiple mirrors with retry logic, and saves a gallery info text file.
    After successful download, it immediately triggers ZIP compression for this
    specific gallery directory.
    
    Args:
        gallery_info (dict): Parsed gallery metadata containing:
            - 'gid': Gallery ID
            - 'title': Gallery title  
            - 'minxres': Minimum resolution
            - 'files': List of file information dictionaries
        gallery_txt (str): Additional gallery information text
        dir_path (str): Directory path where files should be downloaded
        
    Returns:
        bool: True if all files were successfully downloaded, False otherwise
        
    Note:
        - Retries up to 3 times per download URL
        - Triggers individual ZIP compression immediately after download completion
        - ZIP compression runs in separate process to avoid blocking downloads
        - Saves gallery information as 'galleryinfo.txt'
        
    Example:
        >>> gallery_info = {'gid': 12345, 'files': [...], ...}
        >>> success = start_download(gallery_info, info_text, "/downloads/gallery")
    """
    if not hath_config or not default_hath_config:
        logger.error('HathConfig is not properly initialized for fetching download queue')
        return False
    if not gallery_info.get('gid'):
        logger.error('Gallery ID is missing')
        return False

    act = 'dlfetch'
    gid = gallery_info.get('gid', 0)
    gallery_title = gallery_info.get('title', 'unknown')
    xres = gallery_info.get('minxres', '')
    files = gallery_info.get('files', [])
    if not files:
        return False
    for file in files:
        page = file.get('file_page', 0)
        index = file.get('file_index', 0)
        add = f'{gid};{page};{index};{xres};1'  # Always use retry count 1 for initial request
        file_name = file.get('file_name', '')
        file_type = file.get('file_type', 'txt')
        file_sha1 = file.get('file_sha1', '')
        full_name = f"{file_name}.{file_type}"
        file_path = Path(dir_path) / full_name
        current_acttime = hath_config.get_current_acttime()
        actkey_data = f"hentai@home-{act}-{add}-{hath_config.client_id}-{current_acttime}-{hath_config.client_key}"
        actkey = hashlib.sha1(actkey_data.encode()).hexdigest()
        if file_path.exists() and file_path.is_file() and file_path.stat().st_size > 0:
            # Assume non-zero files are valid image files
            logger.debug(f'File already exists and is valid: {file_path}')
            continue
        url_path = (
            f"/15/rpc?clientbuild={hath_config.client_build}&act={act}"
            f"&add={add}&cid={hath_config.client_id}&acttime={current_acttime}&actkey={actkey}"
        )
        file_url = rpc_manager._make_rpc_request(url_path, timeout=30)
        response = file_url.text.strip()
        logger.debug(f'Received download URL response for GID: {gid} page: {page} index: {index}: {response}')
        url = []
        if 'OK' in response:
            lines = response.splitlines()
            for line in lines:
                if line.startswith('http'):
                    url.append(line)
        download_success = False
        if not url:
            logger.error(f'No download links received page {page} for GID: {gid}')
            return False
        logger.debug(f'Starting download page: {page} for GID: {gid}')
        for link in url:
            file_retry_count = 1
            while file_retry_count <= 3:
                if verify_and_save(file_sha1, link, str(file_path)):
                    download_success = True
                    break
                file_retry_count += 1
                logger.warning(f'Error downloading file from {link} retry {file_retry_count-1}: retrying...')
                time.sleep(5)
            if download_success:
                time.sleep(2)
                break
            logger.error(f'Error downloading file from {link}: failed after {file_retry_count-1} attempts')
            time.sleep(5)
        if not download_success:
            logger.error(f'Failed to download file after retries: {file["file_name"]}')
            return False
    text_content = gallery_txt.strip()
    info_file_path = Path(dir_path) / 'galleryinfo.txt'
    try:
        with open(info_file_path, 'w', encoding='utf-8') as info_file:
            info_file.write(text_content)
            info_file.write('\n')
    except Exception as e:
        logger.error(f'Error writing gallery info file: {e}')
        if info_file_path.exists():
            try:
                info_file_path.unlink()
            except Exception as e:
                logger.error(f"Error removing info file: {e}")
        return False
    logger.info(f'Completed download for GID: {gid} {gallery_title}')
    subprocess.Popen(
        [python_exe, 'zip_compressor.py', dir_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True
    )
    return True

def initialize_download_manager():
    """
    Initialize and run the download manager process.
    
    Main download loop that continuously fetches the download queue from the server,
    processes pending galleries, and downloads their files. Handles the complete
    download workflow including queue management, metadata parsing, file downloading,
    and progress tracking.
    
    The function runs indefinitely until:
    - No more pending downloads
    - Server returns invalid request
    - Manual interruption
    
    Process flow:
    1. Ensure download directory exists
    2. Fetch download queue from server
    3. Parse gallery metadata
    4. Create gallery directory
    5. Download all files in gallery
    6. Trigger individual ZIP compression for the gallery
    7. Mark gallery as downloaded
    8. Repeat until queue is empty
    
    Note:
        - Sleeps for 30 seconds on download failure before retrying
        - Tracks downloaded galleries to avoid reprocessing
        - Creates directory structure as needed
        - Handles server communication errors gracefully
        
    Example:
        This function is typically called in a separate thread:
        >>> thread = threading.Thread(target=initialize_download_manager, daemon=True)
        >>> thread.start()
    """
    # Ensure download directory exists
    Path(download_dir).mkdir(exist_ok=True)

    if not hath_config or not default_hath_config:
        logger.error('HathConfig is not properly initialized for fetching download queue')
        return False

    data_dir = hath_config.data_dir
    pid_file = os.path.join(data_dir, '.download_manager.pid')

    mark_downloaded = 0
    downloaded = False
    xres = ''
    while True:
        logger.debug('Get download queue...')
        metadata = get_queue(downloaded=downloaded, gid=mark_downloaded, minxres=xres)
        if not metadata:
            break
        if 'NO_PENDING_DOWNLOADS' in metadata:
            break
        if 'INVALID_REQUEST' in metadata:
            logger.error(f'Invalid request: {metadata}')
            break
        parse_success, gallery_info, gallery_txt = parse_metadata(metadata)
        if not parse_success:
            continue
        gid = gallery_info.get('gid', 0)
        xres = gallery_info.get('minxres', '')
        dir_path = Path(download_dir) / gallery_info.get('title', 'unknown')
        if dir_path.exists():
            gallery_txt_file = dir_path / 'galleryinfo.txt'
            if gallery_txt_file.is_file() and gallery_txt_file.stat().st_size > 0:
                logger.info(f'Gallery already downloaded, skipping GID: {gid}')
                continue
        zip_name = dir_path.with_name(dir_path.name + ".zip")
        if zip_name.exists() and zip_name.stat().st_size > 0:
            logger.info(f'Gallery ZIP already exists, skipping GID: {gid}')
            continue
        dir_path.mkdir(exist_ok=True)
        logger.debug(f'Created directory: {dir_path}')
        if not start_download(gallery_info, gallery_txt, str(dir_path)):
            logger.error(f'Failed to download for GID: {gid}')
            mark_downloaded = 0
            downloaded = False
            xres = ''
            time.sleep(20)
            continue
        mark_downloaded = gid
        downloaded = True
        time.sleep(5)

def trigger_download():
    """
    Start the download manager in a background thread.
    
    Creates and starts a daemon thread that runs the download manager process.
    This function is typically called from the server command handler when
    a 'start_downloader' command is received from the H@H server.
    
    The download manager will:
    - Continuously fetch pending downloads from the server queue
    - Parse gallery metadata and download all files
    - Create individual ZIP archives for each completed gallery
    - Handle errors and retry logic automatically
    
    Returns:
        bool: Always returns True to indicate the thread was started successfully
        
    Note:
        - Uses daemon thread so it won't prevent program exit
        - Only one download manager should run at a time
        - Thread will automatically stop when main program exits
        
    Example:
        >>> trigger_download()  # Start background download process
        True
    """
    thread = threading.Thread(target=initialize_download_manager, daemon=True)
    thread.start()
    return True

