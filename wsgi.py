#!/usr/bin/env python3
"""
WSGI entry point for Hentai@Home Flask client

This is used by Gunicorn workers. The main initialization is handled
by run_gunicorn.py before workers are started.
"""
import os
import sys

# Add the application directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

from app_manager import create_app

# Create the application instance
# In Gunicorn mode, configuration should already be initialized by run_gunicorn.py
application = create_app()

if __name__ == "__main__":
    # Development mode - run Flask directly
    application.run()
