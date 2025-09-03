import os
import shutil

from config_singleton import get_hath_config
import logging

logger = logging.getLogger(__name__)

DEFAULT_MIN_FREE_BYTES = 1073741824

def is_disk_ok():
    '''
    Check if there is enough free disk space in the 'cache' directory,
    using the minimum threshold from hath_config (diskremaining_bytes).
    If not set, default to 1GB.
    '''
    hath_config = get_hath_config()
    if not hath_config:
        logger.error('hath_config not available for notification')
        return False

    config_min_free = hath_config.config.get('diskremaining_bytes')

    try:
        min_free = int(config_min_free) if config_min_free is not None else DEFAULT_MIN_FREE_BYTES
    except (TypeError, ValueError):
        logger.error(f'Invalid diskremaining_bytes value in config: {config_min_free!r}; using default ({DEFAULT_MIN_FREE_BYTES} bytes)')
        min_free = DEFAULT_MIN_FREE_BYTES

    cache_dir = 'cache'
    if not os.path.exists(cache_dir):
        logger.warning(f'Cache directory {cache_dir} does not exist, creating it.')
        os.makedirs(cache_dir, exist_ok=True)

    try:
        total, used, free = shutil.disk_usage(cache_dir)
    except Exception as e:
        logger.error(f'Failed to get disk usage for {cache_dir}: {e}')
        return False

    if int(free) <= min_free:
        logger.warning(f'Not enough disk space: free={free} bytes, minimum required={min_free} bytes')
        return False

    logger.debug(f'Disk space check passed: free={free} bytes')
    return True