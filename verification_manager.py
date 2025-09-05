import hashlib
import time
import logging

from config_singleton import get_hath_config

logger = logging.getLogger(__name__)

def verify_servercmd_key(command: str, additional: str, time_param: str, provided_key: str) -> bool:
    """Verify the authentication key for servercmd endpoint."""
    hath_config = get_hath_config()
    if not hath_config or not hath_config.client_id or not hath_config.client_key:
        return False

    # Generate expected key: SHA-1 of "hentai@home-servercmd-{command}-{additional}-{client_id}-{time}-{client_key}"
    data = f"hentai@home-servercmd-{command}-{additional}-{hath_config.client_id}-{time_param}-{hath_config.client_key}"
    expected_key = hashlib.sha1(data.encode()).hexdigest()

    return provided_key == expected_key


def verify_speed_test_key(testsize: str, testtime: str, provided_key: str) -> bool:
    """Verify the authentication key for /t/ speed test endpoint."""
    hath_config = get_hath_config()
    if not hath_config or not hath_config.client_id or not hath_config.client_key:
        return False

    # Generate expected key: SHA-1 of "hentai@home-speedtest-{testsize}-{testtime}-{client_id}-{client_key}"
    data = f"hentai@home-speedtest-{testsize}-{testtime}-{hath_config.client_id}-{hath_config.client_key}"
    expected_key = hashlib.sha1(data.encode()).hexdigest()

    return provided_key == expected_key


def verify_h_endpoint_auth(keystamp: str, expected: str, file_id: str) -> bool:
    """Verify authentication for /h/ endpoint."""
    hath_config = get_hath_config()
    if not hath_config or not hath_config.client_key:
        return False

    try:
        # Check if keystamp is within 900 seconds (15 minutes)
        current_time = int(time.time())
        keystamp_int = int(keystamp)
        time_diff = abs(current_time - keystamp_int)
        
        if time_diff > 900:
            logger.warning(f"Keystamp too old: {time_diff} seconds difference")
            return False
        
        # Generate expected hash: first 10 chars of "{keystamp}-{fileid}-{client_key}-hotlinkthis"
        hash_data = f"{keystamp}-{file_id}-{hath_config.client_key}-hotlinkthis"
        full_hash = hashlib.sha1(hash_data.encode()).hexdigest()
        expected_hash = full_hash[:10]
        
        return expected == expected_hash
        
    except ValueError:
        logger.warning(f"Invalid keystamp format: {keystamp}")
        return False
