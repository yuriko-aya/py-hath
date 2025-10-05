#!/usr/bin/env python3
'''
Run the Hentai@Home Flask client using Gunicorn WSGI server

This is the recommended way to deploy the H@H client in production.
Uses the virtual environment's gunicorn with proper SSL configuration.

Usage:
    python run_gunicorn.py

Features:
- Virtual environment integration
- SSL/TLS 1.2 and 1.3 support
- Multi-process coordination
- Proper certificate handling
- Production-ready configuration
'''
import argparse
import os
import sys
import logging
import subprocess
import db_manager as db
import log_manager
import settings
import config_manager

def main():
    # defaults + settings.py
    config = {
        'workers': getattr(settings, 'workers', 4),
        'zip_downloaded': getattr(settings, 'zip_downloaded', True),
        'data_dir': getattr(settings, 'data_dir', 'data'),
        'cache_dir': getattr(settings, 'cache_dir', 'cache'),
        'log_dir': getattr(settings, 'log_dir', 'log'),
        'override_port': getattr(settings, 'override_port', False),
        'hath_port': getattr(settings, 'hath_port', 443),
        'log_level': getattr(settings, 'log_level', 'DEBUG'),
        'override_log': False,
        'config_dir': getattr(settings, 'config_dir', 'config'),
        'disable_ip_check': getattr(settings, 'disable_ip_check', 'config'),
        'download_proxy': getattr(settings, 'download_proxy', None),
        'rpc_proxy': getattr(settings, 'rpc_proxy', None)
    }

    # CLI args
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
    parser.add_argument('--download-proxy', help='Proxy for gallery download: socks5://user:password@127.0.0.1:1080')
    parser.add_argument('--rpc-proxy', help='Proxy for RPC requests: socks5://user:password@127.0.0.1:1080')
    args = parser.parse_args()

    # validation
    if args.override_port and args.port is None:
        parser.error('--override-port requires --port to be set')

    # apply overrides
    if args.workers is not None:
        config['workers'] = args.workers
    if args.log_dir is not None:
        config['log_dir'] = args.log_dir
    if args.data_dir is not None:
        config['data_dir'] = args.data_dir
    if args.cache_dir is not None:
        config['cache_dir'] = args.cache_dir
    if args.override_port:
        config['override_port'] = True
    if args.port is not None:
        config['hath_port'] = args.port
    if args.no_zip:
        config['zip_downloaded'] = False
    if args.disable_ip_check:
        config['disable_ip_check'] = True
    if args.download_proxy is not None:
        config['download_proxy'] = args.download_proxy
    if args.rpc_proxy is not None:
        config['rpc_proxy'] = args.rpc_proxy

    if args.log_level is not None:
        config['log_level'] = args.log_level

    if config['log_level'] is not None:
        config['override_log'] = True

    # Check necessary directory and create it if not exists
    os.makedirs(config.get('log_dir', 'log'), exist_ok=True)
    os.makedirs(config.get('cache_dir', 'cache'), exist_ok=True)
    os.makedirs(config.get('data_dir', 'data'), exist_ok=True)
    os.makedirs(config.get('config_dir', 'config'), exist_ok=True)

    log_manager.setup_file_logging(config.get('log_dir', 'log'))
    logging.debug(f'File logging initialized - logs will be stored in "{config.get('log_dir', 'log')}" directory')
    logging.debug('Log files: hath_client.log')
    logging.debug('Log rotation is handled by system logrotate (multiprocess-safe)')

    logger = logging.getLogger(__name__)
    logger.info('Initializing Hentai@Home client for Gunicorn deployment...')

    # Initialize hath_config here in the main process before starting workers
    hath_config = config_manager.Config()

    if not config_manager.initialize(config):
        logger.error('Failed to initialize configuration')
        sys.exit(1)

    # Initialize logging for background tasks
    if config['override_log']:
        log_level = config['log_level'].upper()
        numeric_level = getattr(logging, log_level, None)
        if not isinstance(numeric_level, int):
            logger.error(f'Invalid log level: {config["log_level"]}')
            sys.exit(1)
        logger.info(f'Log level overridden to {log_level}')
        logger.setLevel(numeric_level)
    elif hath_config and hath_config.config.get('disable_logging', False):
        logger.info('Setting log level to WARNING as per configuration')
        logger.setLevel(logging.WARNING)
    else:
        logger.info('Using default log level from settings or config')

    # Import modules that depend on hath_config (now using singleton)
    import cache_manager
    import background_manager
    import event_manager

    # Validate cache before starting workers
    missing_db = db.initialize_database()
 
    cache_manager.cache_validation(force_rescan=missing_db)

    # Set up shutdown handlers for graceful cleanup
    background_manager.setup_shutdown_handlers()

    # Start server startup notification and background tasks
    background_manager.start_background_task()

    # Now we can use the logger
    logger.info('Configuration initialized successfully')

    # Get configuration from hath_config
    if not hath_config:
        logger.error('Configuration not available')
        sys.exit(1)
        
    flask_config = hath_config.config

    host = flask_config['host']

    if config['override_port']:
        port = config['hath_port']
    else:
        port = flask_config['port']

    if not host or not port:
        logger.error('Invalid host or port configuration')
        sys.exit(1)

    # Get SSL certificate paths directly from hath_config, not from Flask config
    # Flask's ssl_context is only used when running Flask directly
    cert_file_path = hath_config.cert_file
    key_file_path = hath_config.key_file

    logger.info(f'Starting Gunicorn server on {host}:{port}')

    # Hentai@Home requires HTTPS - enforce SSL-only operation
    if not cert_file_path or not key_file_path:
        logger.error('SSL certificates not available - Hentai@Home requires HTTPS operation')
        logger.error('Please ensure SSL certificates are properly configured in hath_config')
        sys.exit(1)

    logger.info(f'SSL enabled with certificate: {cert_file_path}')
    logger.info(f'SSL key file: {key_file_path}')
    logger.info('SSL configuration: TLS 1.2 and 1.3 supported (auto-negotiation)')
    logger.info('Strong cipher suites enabled for enhanced security')

    # Verify certificate files exist
    if not os.path.exists(cert_file_path):
        logger.error(f'SSL certificate file not found: {cert_file_path}')
        sys.exit(1)
    if not os.path.exists(key_file_path):
        logger.error(f'SSL key file not found: {key_file_path}')
        sys.exit(1)

    # Build Gunicorn command - use the virtual environment's gunicorn
    # This script provides all necessary configuration via command-line parameters

    # Get the path to the virtual environment's gunicorn executable
    venv_python = sys.executable
    venv_dir = os.path.dirname(os.path.dirname(venv_python))  # Go up two levels from python to venv root
    gunicorn_executable = os.path.join(venv_dir, 'bin', 'gunicorn')

    # Fallback to system gunicorn if virtual env gunicorn not found
    if not os.path.exists(gunicorn_executable):
        logger.warning(f'Virtual environment gunicorn not found at {gunicorn_executable}')
        logger.warning('Falling back to system gunicorn - this may cause import issues')
        gunicorn_executable = 'gunicorn'
    else:
        logger.info(f'Using virtual environment gunicorn: {gunicorn_executable}')

    gunicorn_cmd = [
        gunicorn_executable,
        '--bind', f'{host}:{port}',
        '--certfile', cert_file_path,
        '--keyfile', key_file_path,
        '--pid', 'config/gunicorn.pid',
        '--workers', str(config['workers']),
        'wsgi:application'
    ]

    try:
        logger.info('Starting HTTPS server with Gunicorn (SSL required for Hentai@Home)...')
        logger.debug(f'Command: {" ".join(gunicorn_cmd)}')
        
        # Execute Gunicorn
        subprocess.run(gunicorn_cmd, check=True)
        
    except KeyboardInterrupt:
        logger.info('Shutdown signal received, stopping server...')
    except subprocess.CalledProcessError as e:
        logger.error(f'Gunicorn process failed with exit code {e.returncode}')
        sys.exit(1)
    except FileNotFoundError:
        logger.error('Gunicorn not found - please install with: pip install gunicorn')
        sys.exit(1)
    except Exception as e:
        logger.error(f'Error starting HTTPS server: {e}')
        logger.error('Please check SSL certificate configuration and try again')
        sys.exit(1)

if __name__ == '__main__':
    main()
