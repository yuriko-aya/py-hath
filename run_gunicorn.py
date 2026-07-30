#!/usr/bin/env python3
'''
Run the Hentai@Home Flask client using Gunicorn WSGI server
'''
import argparse
import logging
import os
import subprocess
import sys

import config_manager
import db_manager as db
import log_manager
import settings
from hath.validation import validate_startup_config


def _env_flag(name: str) -> bool:
    return os.environ.get(name, '').strip().lower() in ('1', 'true', 'yes')


def _build_config(args) -> dict:
    config = {
        'workers': getattr(settings, 'workers', 4),
        'worker_class': getattr(settings, 'worker_class', 'sync'),
        'zip_downloaded': getattr(settings, 'zip_downloaded', True),
        'data_dir': getattr(settings, 'data_dir', 'data'),
        'cache_dir': getattr(settings, 'cache_dir', 'cache'),
        'download_dir': getattr(settings, 'download_dir', 'download'),
        'log_dir': getattr(settings, 'log_dir', 'log'),
        'config_dir': getattr(settings, 'config_dir', 'config'),
        'override_port': getattr(settings, 'override_port', False),
        'hath_port': getattr(settings, 'hath_port', 443),
        'log_level': getattr(settings, 'log_level', None),
        'override_log': False,
        'disable_ip_check': getattr(settings, 'disable_ip_check', False),
        'trust_x_forwarded_for': getattr(settings, 'trust_x_forwarded_for', False),
        'download_proxy': getattr(settings, 'download_proxy', None),
        'rpc_proxy': getattr(settings, 'rpc_proxy', None),
        'json_logs': getattr(settings, 'json_logs', False),
    }

    if _env_flag('HATH_DEBUG'):
        config['log_level'] = 'DEBUG'
        config['override_log'] = True

    if args.workers is not None:
        config['workers'] = args.workers
    if args.log_dir is not None:
        config['log_dir'] = args.log_dir
    if args.data_dir is not None:
        config['data_dir'] = args.data_dir
    if args.cache_dir is not None:
        config['cache_dir'] = args.cache_dir
    if args.config_dir is not None:
        config['config_dir'] = args.config_dir
    if args.override_port:
        config['override_port'] = True
    if args.port is not None:
        config['hath_port'] = args.port
    if args.no_zip:
        config['zip_downloaded'] = False
    if args.disable_ip_check:
        config['disable_ip_check'] = True
    if args.trust_x_forwarded_for:
        config['trust_x_forwarded_for'] = True
    if args.download_proxy is not None:
        config['download_proxy'] = args.download_proxy
    if args.rpc_proxy is not None:
        config['rpc_proxy'] = args.rpc_proxy
    if args.log_level is not None:
        config['log_level'] = args.log_level

    if config['log_level'] is not None:
        config['override_log'] = True
    elif config['log_level'] is None:
        config['log_level'] = 'DEBUG'

    return config


def main():
    parser = argparse.ArgumentParser(description='Run Hentai@Home client with Gunicorn')
    parser.add_argument('--workers', type=int, help='Number of Gunicorn worker processes')
    parser.add_argument('--log-level', help='Logging level (DEBUG, INFO, WARNING, ERROR)')
    parser.add_argument('--log-dir', help='Log file path')
    parser.add_argument('--data-dir', help='Data directory for SSL certs and DB')
    parser.add_argument('--cache-dir', help='Cache directory')
    parser.add_argument('--override-port', action='store_true', help='Use hath override port')
    parser.add_argument('--port', type=int, help='Hath port (default 443 for HTTPS)')
    parser.add_argument('--no-zip', action='store_true', help='Disable ZIP compression for downloaded galleries')
    parser.add_argument('--config-dir', help='Configuration directory')
    parser.add_argument('--disable-ip-check', action='store_true', help='Disable source IP check')
    parser.add_argument('--trust-x-forwarded-for', action='store_true', help='Trust X-Forwarded-For for servercmd IP checks')
    parser.add_argument('--download-proxy', help='Proxy for gallery download')
    parser.add_argument('--rpc-proxy', help='Proxy for RPC requests')
    args = parser.parse_args()

    if args.override_port and args.port is None:
        parser.error('--override-port requires --port to be set')

    config = _build_config(args)

    errors = validate_startup_config(config)
    if errors:
        for err in errors:
            print(f'Configuration error: {err}', file=sys.stderr)
        sys.exit(1)

    os.makedirs(config['log_dir'], exist_ok=True)
    os.makedirs(config['cache_dir'], exist_ok=True)
    os.makedirs(config['data_dir'], exist_ok=True)
    os.makedirs(config['download_dir'], exist_ok=True)
    os.makedirs(config['config_dir'], exist_ok=True)

    log_manager.setup_file_logging(config['log_dir'], json_logs=config['json_logs'])
    logger = logging.getLogger(__name__)
    logger.info('Initializing Hentai@Home client for Gunicorn deployment...')

    hath_config = config_manager.Config()

    if not config_manager.initialize(config):
        logger.error('Failed to initialize configuration')
        sys.exit(1)

    if config['override_log']:
        log_level = config['log_level'].upper()
        numeric_level = getattr(logging, log_level, None)
        if not isinstance(numeric_level, int):
            logger.error(f'Invalid log level: {config["log_level"]}')
            sys.exit(1)
        logger.info(f'Log level overridden to {log_level}')
        logging.getLogger().setLevel(numeric_level)
        log_manager.set_file_log_level(numeric_level)
    elif hath_config.config.get('disable_logging', False):
        logger.info('Setting log level to WARNING as per configuration')
        logging.getLogger().setLevel(logging.WARNING)
        log_manager.set_file_log_level(logging.WARNING)

    import background_manager
    import cache_manager

    missing_db = db.initialize_database()
    cache_manager.cache_validation(force_rescan=missing_db)
    background_manager.setup_shutdown_handlers()
    background_manager.start_background_task()

    logger.info('Configuration initialized successfully')

    flask_config = hath_config.config
    host = flask_config['host']
    port = config['hath_port'] if config['override_port'] else flask_config['port']

    if not host or not port:
        logger.error('Invalid host or port configuration')
        sys.exit(1)

    cert_file_path = hath_config.cert_file
    key_file_path = hath_config.key_file

    if not cert_file_path or not key_file_path:
        logger.error('SSL certificates not available - Hentai@Home requires HTTPS operation')
        sys.exit(1)

    if not os.path.exists(cert_file_path) or not os.path.exists(key_file_path):
        logger.error('SSL certificate or key file not found')
        sys.exit(1)

    logger.info(f'Starting Gunicorn server on {host}:{port}')

    venv_python = sys.executable
    venv_dir = os.path.dirname(os.path.dirname(venv_python))
    gunicorn_executable = os.path.join(venv_dir, 'bin', 'gunicorn')
    if not os.path.exists(gunicorn_executable):
        logger.warning('Virtual environment gunicorn not found; falling back to system gunicorn')
        gunicorn_executable = 'gunicorn'

    conf_path = os.path.join(os.path.dirname(__file__), 'gunicorn.conf.py')
    pid_path = os.path.join(config['config_dir'], 'gunicorn.pid')

    os.environ['HATH_WORKERS'] = str(config['workers'])
    os.environ['HATH_WORKER_CLASS'] = config['worker_class']
    os.environ['HATH_BIND'] = f'{host}:{port}'
    os.environ['HATH_CERTFILE'] = cert_file_path
    os.environ['HATH_KEYFILE'] = key_file_path
    os.environ['HATH_PIDFILE'] = pid_path
    os.environ['HATH_ACCESSLOG'] = os.path.join(config['log_dir'], 'gunicorn_access.log')
    os.environ['HATH_ERRORLOG'] = os.path.join(config['log_dir'], 'gunicorn_error.log')

    gunicorn_cmd = [
        gunicorn_executable,
        '-c', conf_path,
        'wsgi:application',
    ]

    try:
        logger.info('Starting HTTPS server with Gunicorn (SSL required for Hentai@Home)...')
        subprocess.run(gunicorn_cmd, check=True)
    except KeyboardInterrupt:
        logger.info('Shutdown signal received, stopping server...')
    except subprocess.CalledProcessError as e:
        logger.error(f'Gunicorn process failed with exit code {e.returncode}')
        sys.exit(1)
    except FileNotFoundError:
        logger.error('Gunicorn not found - please install with: pip install gunicorn')
        sys.exit(1)


if __name__ == '__main__':
    main()
