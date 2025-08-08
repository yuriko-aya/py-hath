#!/bin/bash

# Simple run script for Hentai@Home Python Client

echo "Starting Hentai@Home Python Client..."

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not found"
    exit 1
fi

# Install dependencies if requirements.txt exists
if [ -f "requirements.txt" ]; then
    echo "Installing/checking Python dependencies..."
    python3 -m pip install -r requirements.txt --quiet
fi

# Run the client
echo "Launching client..."
python3 main.py "$@"
