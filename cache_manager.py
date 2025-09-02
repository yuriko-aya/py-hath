import db_manager as db
import logging
import os
import shutil
import hashlib
import requests

from config_singleton import get_hath_config
from pathlib import Path

logger = logging.getLogger(__name__)

def cache_validation(missing_db=False, force_rescan=False):
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
        if not missing_db:
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
                l1dir = prefix[:2]
                l2dir = prefix[2:4]
                dir_path = os.path.join(cache_dir, l1dir, l2dir)
                if os.path.exists(dir_path) and os.path.isdir(dir_path):
                    shutil.rmtree(dir_path)
                    logger.debug(f"Removed directory for illegal prefix: {dir_path}")
                    db.remove_static_range(prefix)
                else:
                    logger.debug(f"Illegal directory {dir_path} does not exist. Cleaning up from database")
                    db.remove_static_range(prefix)
            return True
        if missing_db or force_rescan:
            if force_rescan:
                db.clean_up_data()
            logger.debug("Missing/empty database or force rescan requested, proceeding with full cache validation...")
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
                    logger.debug(f"Cache cleanup... ({verified_percent:.1f}%)")

                if static_name not in static_range:
                    # Delete files with prefixes not in static range
                    os.remove(file)
                    deleted_count += 1
                    db.update_file_count(static_name, removal=True)
                else:
                    # File is in static range, keep it
                    db.update_file_count(static_name)
                
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
        f"/15/rpc?clientbuild=176&act=get_blacklist"
        f"&add={add}&cid={hath_config.client_id}&acttime={current_acttime}&actkey={actkey}"
    )
    resp = hath_config._make_rpc_request(url_path, timeout=20)
    delete_count = 0
    if 'OK' in resp.text:
        logger.debug(f'Receive response {resp.text}')
        for line in resp.text.splitlines():
            if '-' in line:
                static_range = line[:4]
                l1dir = line[:2]
                l2dir = line[2:4]

                if os.path.exists(os.path.join('cache', l1dir, l2dir, line)):
                    os.remove(os.path.join('cache', l1dir, l2dir, line))
                    db.update_file_count(static_range, removal=True)
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
            f"/15/rpc?clientbuild=176&act=srfetch"
            f"&add={add}&cid={hath_config.client_id}&acttime={current_acttime}&actkey={actkey}"
        )
        logger.debug(f"Fetching file location via RPC: {url_path}")
        resp = hath_config._make_rpc_request(url_path, timeout=20)
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
                    file_resp = requests.get(url, timeout=10, stream=True)
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
