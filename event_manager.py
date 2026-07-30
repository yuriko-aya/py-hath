import logging
import os
import signal

from hath.paths import get_config_dir

logger = logging.getLogger(__name__)


def restart_gunicorn():
    try:
        pid_path = os.path.join(get_config_dir(), 'gunicorn.pid')
        with open(pid_path, 'r') as f:
            pid = int(f.read().strip())
        logger.info(f'Sending SIGUSR2 to Gunicorn master process... PID: {pid}')
        os.kill(pid, signal.SIGUSR2)
    except Exception as e:
        logger.error(f"Failed to restart Gunicorn: {e}")
