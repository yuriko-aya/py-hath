#!/usr/bin/env python3
"""
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
"""
import os
import sys
import logging
import subprocess

def main():
    # Check necessary directory and create it if not exists
    os.makedirs('log', exist_ok=True)
    os.makedirs('cache', exist_ok=True)
    os.makedirs('data', exist_ok=True)

    # Import and create the application to initialize configuration
    from app import create_app
    
    # Create the app first to initialize logging and hath_config
    app = create_app()
    
    # Now import hath_config after it's been initialized by create_app
    from app import hath_config
    
    # Now we can use the app's logger
    logger = logging.getLogger(__name__)
    logger.info("Creating Flask application for Gunicorn deployment...")
    
    # Get configuration from hath_config
    if not hath_config:
        logger.error("Configuration not available")
        sys.exit(1)
        
    flask_config = hath_config.get_flask_config()
    
    host = flask_config['host']
    port = flask_config['port']
    
    # Get SSL certificate paths directly from hath_config, not from Flask config
    # Flask's ssl_context is only used when running Flask directly
    cert_file_path = hath_config.cert_file
    key_file_path = hath_config.key_file
    
    logger.info(f"Starting Gunicorn server on {host}:{port}")
    
    # Hentai@Home requires HTTPS - enforce SSL-only operation
    if not cert_file_path or not key_file_path:
        logger.error("SSL certificates not available - Hentai@Home requires HTTPS operation")
        logger.error("Please ensure SSL certificates are properly configured in hath_config")
        sys.exit(1)
    
    logger.info(f"SSL enabled with certificate: {cert_file_path}")
    logger.info(f"SSL key file: {key_file_path}")
    logger.info("SSL configuration: TLS 1.2 and 1.3 supported (auto-negotiation)")
    logger.info("Strong cipher suites enabled for enhanced security")
    
    # Verify certificate files exist
    if not os.path.exists(cert_file_path):
        logger.error(f"SSL certificate file not found: {cert_file_path}")
        sys.exit(1)
    if not os.path.exists(key_file_path):
        logger.error(f"SSL key file not found: {key_file_path}")
        sys.exit(1)
    
    # Build Gunicorn command - use the virtual environment's gunicorn
    # This script provides all necessary configuration via command-line parameters
    
    # Get the path to the virtual environment's gunicorn executable
    venv_python = sys.executable
    venv_dir = os.path.dirname(os.path.dirname(venv_python))  # Go up two levels from python to venv root
    gunicorn_executable = os.path.join(venv_dir, 'bin', 'gunicorn')
    
    # Fallback to system gunicorn if virtual env gunicorn not found
    if not os.path.exists(gunicorn_executable):
        logger.warning(f"Virtual environment gunicorn not found at {gunicorn_executable}")
        logger.warning("Falling back to system gunicorn - this may cause import issues")
        gunicorn_executable = 'gunicorn'
    else:
        logger.info(f"Using virtual environment gunicorn: {gunicorn_executable}")
    
    gunicorn_cmd = [
        gunicorn_executable,
        '--bind', f'{host}:{port}',
        '--workers', '4',
        '--worker-class', 'gevent',
        '--timeout', '10',
        '--keep-alive', '2',
        '--max-requests', '1000',
        '--max-requests-jitter', '100',
        '--access-logfile', 'log/gunicorn_access.log',
        '--error-logfile', 'log/gunicorn_error.log',
        '--log-level', 'info',
        '--certfile', cert_file_path,
        '--keyfile', key_file_path,
        '--ciphers', 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS',
        'wsgi:application'
    ]
    
    try:
        logger.info("Starting HTTPS server with Gunicorn (SSL required for Hentai@Home)...")
        logger.info(f"Command: {' '.join(gunicorn_cmd)}")
        
        # Execute Gunicorn
        subprocess.run(gunicorn_cmd, check=True)
        
    except KeyboardInterrupt:
        logger.info("Shutdown signal received, stopping server...")
    except subprocess.CalledProcessError as e:
        logger.error(f"Gunicorn process failed with exit code {e.returncode}")
        sys.exit(1)
    except FileNotFoundError:
        logger.error("Gunicorn not found - please install with: pip install gunicorn")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error starting HTTPS server: {e}")
        logger.error("Please check SSL certificate configuration and try again")
        sys.exit(1)

if __name__ == '__main__':
    main()
