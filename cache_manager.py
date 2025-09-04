import db_manager as db
import logging
import os
import shutil
import hashlib
import requests
import time
import rpc_manager

from config_singleton import get_hath_config
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)
requests_headers = {
    'User-Agent': 'Hentai@Home Python Client 0.2'
}

def delete_static_range(static_range: str):
    '''Delete static range and all file inside it'''
    l1dir = static_range[:2]
    l2dir = static_range[2:4]
    dir_path = os.path.join('cache', l1dir, l2dir)
    if not os.path.exists(dir_path) or not os.path.isdir(dir_path):
        logger.warning(f"Directory for static range {static_range} does not exist: {dir_path}")
        db.remove_static_range(static_range)
        return
    files = [p for p in Path(dir_path).glob(f'*') if p.is_file()]
    for file in files:
        file_size = file.stat().st_size
        db.update_file_count(static_range, removal=True)
        db.update_file_size(file_size, removal=True)
    shutil.rmtree(dir_path)
    db.remove_static_range(static_range)

def cache_validation(force_rescan=False):
    """Validate the cache state before notifying the server."""
    logger.info("Starting cache validation...")
    hath_config = get_hath_config()
    if not hath_config or not hath_config.client_id or not hath_config.client_key:
        logger.error("Configuration not available for cache validation")
        return False

    try:
        cache_dir = 'cache'
        static_range = hath_config.static_range
        if not static_range or len(static_range) == 0:
            logger.debug("No static range defined, skipping cache validation")
            return True  # Nothing to validate
        illegal_static_range = []
        if not force_rescan:
            logger.debug("Loading data from database...")
            local_static_range = db.get_static_range_list()
            if len(local_static_range) == 0:
                logger.warning("Database is empty... rescanning...")
                missing_db = True
            elif set(local_static_range).issubset(set(static_range)):
                logger.info("All static ranges in database are in the given list, skipping cache validation")
                return True # All prefixes are valid
            else:
                illegal_static_range = list(set(local_static_range) - set(static_range))
        if illegal_static_range and not force_rescan:
            logger.warning(f"Found {len(illegal_static_range)} illegal static ranges {illegal_static_range}. Cleaning it up...")
            for prefix in illegal_static_range:
                logger.debug(f"Deleting illegal static range {prefix} and all files inside it...")
                delete_static_range(prefix)
            return True
        if force_rescan:
            db.clean_up_data()
            logger.debug("Missing/empty database or force rescan requested, proceeding with full cache validation...")
            logger.debug("loading cache...")
            files = [p for p in Path(cache_dir).glob("*/*/*") if p.is_file()]
            file_count = len(files)
            if not files or len(files) == 0:
                logger.info("Cache is empty. Skipping validation")
                return True

            ten_percent = max(1, file_count // 10)  # Avoid division by zero
            verified_count = 0
            verified_percent = 0
            deleted_count = 0
            for file in files:
                static_name = file.name[:4]
                if verified_count % ten_percent == 0:
                    logger.debug(f"Cache validation... ({verified_percent:.1f}%)")

                if static_name not in static_range:
                    # Delete files with prefixes not in static range
                    file_size = file.stat().st_size
                    os.remove(file)
                    deleted_count += 1
                    logger.debug(f"Deleted file outside static range: {file}")
                    db.update_file_count(static_name, removal=True)
                    db.update_file_size(file_size, removal=True)
                else:
                    # File is in static range, keep it
                    db.update_file_count(static_name)
                    db.update_file_size(file.stat().st_size)
                
                verified_count += 1
                verified_percent = (verified_count / file_count) * 100
                
            logger.info("Cache validation completed successfully")
            if deleted_count > 0:
                logger.warning(f"Deleted {deleted_count} files outside of static range")
        
        return True
        
    except OSError as e:
        logger.error(f"Error accessing cache directory: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during cache validation: {e}")
        return False

def blacklist_process(timespan: int):
    logger.debug(f"Processing blacklist for timespan: {timespan}")
    # Check hath_config before using it
    hath_config = get_hath_config()
    if not hath_config or not getattr(hath_config, 'client_id', None) or not getattr(hath_config, 'client_key', None):
        logger.error("Missing hath_config, client_id or client_key for remote fetch")
        return False, None
    # Prepare actkey and acttime
    current_acttime = hath_config.get_current_acttime()
    add = str(timespan)
    # actkey is SHA-1 of "hentai@home-srfetch-{add}-{client_id}-{current_acttime}-{client_key}"
    if not hath_config or not hath_config.client_id or not hath_config.client_key:
        logger.error("Missing client_id or client_key for remote fetch")
        return False, None
    actkey_data = f"hentai@home-get_blacklist-{add}-{hath_config.client_id}-{current_acttime}-{hath_config.client_key}"
    actkey = hashlib.sha1(actkey_data.encode()).hexdigest()
    url_path = (
        f"/15/rpc?clientbuild={hath_config.client_build}&act=get_blacklist"
        f"&add={add}&cid={hath_config.client_id}&acttime={current_acttime}&actkey={actkey}"
    )
    resp = rpc_manager._make_rpc_request(url_path, timeout=20)
    delete_count = 0
    if 'OK' in resp.text:
        logger.debug(f'Receive response {resp.text}')
        for line in resp.text.splitlines():
            if '-' in line:
                static_range = line[:4]
                l1dir = line[:2]
                l2dir = line[2:4]
                file_path = os.path.join('cache', l1dir, l2dir, line)
                if os.path.exists(file_path):
                    file_size = Path(file_path).stat().st_size
                    os.remove(file_path)
                    db.update_file_count(static_range, removal=True)
                    db.update_file_size(file_size, removal=True)    
                    delete_count += 1

    return delete_count

def verify_file_integrity(file_path:str, file_id:str):
    """Verify the integrity of the cached file by comparing its SHA-1 hash with the file_id."""
    # Extract expected hash from file_id (handle different formats)
    if '-' in file_id:
        expected_hash = file_id.split('-')[0]
    else:
        # If no dash, assume the whole file_id is the hash
        expected_hash = file_id

    try:
        sha1 = hashlib.sha1()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha1.update(chunk)
        file_hash = sha1.hexdigest()
        if not file_hash == expected_hash:
            logger.debug(f"File integrity check failed for {file_path}: expected {expected_hash}, got {file_hash}")
            return False
        else:
            logger.debug(f"File integrity check passed for {file_path}")
            return True
    except Exception as e:
        logger.error(f"Error verifying file integrity: {e}")
        return False

def fetch_remote_file(fileindex: str, xres: str, file_id: str):
    try:
        # Check hath_config before using it
        hath_config = get_hath_config()
        if not hath_config or not getattr(hath_config, 'client_id', None) or not getattr(hath_config, 'client_key', None):
            logger.error("Missing hath_config, client_id or client_key for remote fetch")
            return False, None
        # Prepare actkey and acttime
        current_acttime = hath_config.get_current_acttime()
        add = f"{fileindex};{xres};{file_id}"
        # actkey is SHA-1 of "hentai@home-srfetch-{add}-{client_id}-{current_acttime}-{client_key}"
        if not hath_config or not hath_config.client_id or not hath_config.client_key:
            logger.error("Missing client_id or client_key for remote fetch")
            return False, None
        actkey_data = f"hentai@home-srfetch-{add}-{hath_config.client_id}-{current_acttime}-{hath_config.client_key}"
        actkey = hashlib.sha1(actkey_data.encode()).hexdigest()
        url_path = (
            f"/15/rpc?clientbuild={hath_config.client_build}&act=srfetch"
            f"&add={add}&cid={hath_config.client_id}&acttime={current_acttime}&actkey={actkey}"
        )
        logger.debug(f"Fetching file location via RPC: {url_path}")
        resp = rpc_manager._make_rpc_request(url_path, timeout=20)
        # Find the first line starting with http
        urls = []
        for line in resp.text.splitlines():
            if line.startswith('http'):
                urls.append(line.strip())
        if not urls:
            logger.error("No valid URL found in srfetch response")
            return False, None
        logger.debug(f"Found {len(urls)} URLs in srfetch response: {urls}")
        for url in urls:
            for attempt in range(1, 4):  # up to 3 retries per URL
                try:
                    logger.debug(f"Attempt {attempt} - Downloading file from: {url}")
                    file_resp = requests.get(url, headers=requests_headers, timeout=10, stream=True)
                    file_resp.raise_for_status()
                    logger.debug(f"Successfully downloaded from {url}")
                    return True, file_resp  # ✅ stop immediately after success
                except Exception as e:
                    logger.error(f"Attempt {attempt} - Failed to download {url}: {e}")
            logger.error(f"Max retries reached for {url}")
        logger.error(f"All URLs {urls} failed to download")
        return False, None

    except Exception as e:
        logger.error(f"Remote fetch or download failed: {e}")
        return False, None

def get_throttled_speed():
    hath_config = get_hath_config()
    chunk_size = 8192
    if not hath_config:
        logger.error("hath_config not available for throttled speed calculation")
        return 0

    config_throttled_bytes = hath_config.config.get('throttle_bytes')
    try:
        speed = int(config_throttled_bytes) if config_throttled_bytes is not None else 0
    except (ValueError, TypeError):
        logger.error(f"Invalid throttle_bytes configuration: {config_throttled_bytes}")
        speed = 0

    # Calculate sleep time based on throttled speed
    if speed > 0:
        sleep_time = chunk_size / speed
    else:
        sleep_time = 0

    return sleep_time

def generate_and_cache(file_path, file_id, file_resp, file_size):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    sleep_time = get_throttled_speed()
    # Update last access time for cache tracking
    static_name = file_id[:4]
    success = True
    try:
        with open(file_path, 'wb') as cache_file:
            for chunk in file_resp.iter_content(chunk_size=8192):
                if chunk:
                    cache_file.write(chunk)
                    yield chunk
                    time.sleep(sleep_time)
    except Exception as e:
        logger.error(f"Error generating and caching file {file_path}: {e}")
        yield b'' # Yield empty bytes on error to avoid breaking the response
        success = False
    finally:
        if success:
            logger.debug(f"File cached at: {file_path}")
            db.update_last_access(static_name, new_file=True)
            db.update_file_size(file_size)

def serve_from_file(file_path, file_id):
    sleep_time = get_throttled_speed()
    static_name = file_id[:4]

    try:
        with open(file_path, 'rb') as img_file:
            while chunk := img_file.read(8192):
                yield chunk
                time.sleep(sleep_time)
    except Exception as e:
        logger.error(f"Error serving file {file_path}: {e}")
        yield b''  # Yield empty bytes on error to avoid breaking the response
    finally:
        db.update_last_access(static_name)

def prune_cache():
    '''Prune oldest cache due size limit'''
    oldest_static_file, time_stamp = db.get_oldest_static_range()
    one_week_ago = datetime.now() - timedelta(weeks=1)
    if oldest_static_file and time_stamp:
        static_range_time = datetime.fromtimestamp(time_stamp)
        if static_range_time > one_week_ago:
            logger.error('Oldest static file is less than one week old, not pruning.')
            return False
        else:
            logger.info(f"Pruned oldest static file from cache: {oldest_static_file} due to cache size constraint")
            delete_static_range(oldest_static_file)

def check_cache_size():
    """Check the current cache size and log it."""
    hath_config = get_hath_config()
    if not hath_config:
        logger.error("hath_config not available for cache size check")
        return

    current_cache_size = db.get_cache_size()
    cache_size_limit  = hath_config.config.get('disklimit_bytes')

    try:
        max_cache_size = int(cache_size_limit) if cache_size_limit is not None else 0
    except (TypeError, ValueError):
        logger.warning(f'Invalid disklimit_bytes value in config: {cache_size_limit!r}')
        max_cache_size = 0  # fallback to no limit

    if current_cache_size == 0 or max_cache_size == 0:
        logger.warning('Get zero bytes cache size! Either cache empty or there is problem. Assuming OK')
        return True

    if max_cache_size > 0 and current_cache_size > max_cache_size:
        logger.warning(f'Cache size limit exceeded: current={current_cache_size} bytes, limit={max_cache_size} bytes')
        logger.warning('Start cleaning old static range')
        prune_cache()
        return True
    else:
        logger.debug(f'Cache size is within limits: current={current_cache_size} bytes, limit={max_cache_size} bytes')
        return True
