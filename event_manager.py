import logging
import os
import signal

logger = logging.getLogger(__name__)

def restart_gunicorn():
    try:
        with open('config/gunicorn.pid', 'r') as f:
            pid = int(f.read().strip())
        # SIGUSR2 creates new master process with new SSL certs
        logger.info(f'Sending SIGUSR2 to Gunicorn master process... PID: {pid}')
        os.kill(pid, signal.SIGUSR2)
    except Exception as e:
        logger.error(f"Failed to restart Gunicorn: {e}")