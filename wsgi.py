#!/usr/bin/env python3
"""
WSGI entry point for Hentai@Home Flask client
"""
import os
import sys

# Add the application directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

from app import create_app

# Create the application instance
application = create_app()

if __name__ == "__main__":
    application.run()
