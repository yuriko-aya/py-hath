import json
import logging
import os

logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('requests').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

_file_handler = None


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            'timestamp': self.formatTime(record, self.datefmt),
            'level': record.levelname,
            'logger': record.name,
            'process': record.process,
            'message': record.getMessage(),
        }
        if record.exc_info:
            payload['exception'] = self.formatException(record.exc_info)
        return json.dumps(payload)


def setup_file_logging(log_dir, file_level=logging.DEBUG, json_logs=False):
    """Setup file-based logging handlers."""
    global _file_handler

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(logging.DEBUG)

    if json_logs:
        formatter = JsonFormatter(datefmt='%Y-%m-%d %H:%M:%S')
    else:
        formatter = logging.Formatter(
            '%(asctime)s - [%(process)d] %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
        )

    _file_handler = logging.FileHandler(
        filename=os.path.join(log_dir, 'hath_client.log'),
        encoding='utf-8',
    )
    _file_handler.setFormatter(formatter)
    _file_handler.setLevel(file_level)
    root_logger.addHandler(_file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    root_logger.addHandler(console_handler)


def set_file_log_level(level: int) -> None:
    if _file_handler is not None:
        _file_handler.setLevel(level)
