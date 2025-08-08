# Hentai@Home Python Client

This is a Python implementation of the Hentai@Home client, converted from the original Java version.

## Features

- **Core functionality**: File caching, HTTP server, server communication
- **Command-line interface**: No GUI dependencies
- **Python 3.7+ compatibility**: Modern Python features
- **GPL v3 licensed**: Same license as original

## Requirements

- Python 3.7 or newer
- requests
- cryptography

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Run the client:
```bash
python main.py
```

## Configuration

On first run, you'll be prompted for your Client ID and Key from E-Hentai. These will be saved locally for future runs.

## Command Line Options

- `--disable-file-verification`: Disable SHA1 verification of cached files
- `--use-less-memory`: Use less memory (disables some optimizations)
- `--rescan-cache`: Force rescan of cache on startup
- `--verify-cache`: Verify all cached files on startup
- `--disable-logs`: Disable file logging
- `--flush-logs`: Flush logs immediately
- `--debug` or `--verbose`: Enable debug output to console

## Differences from Java Version

This Python implementation includes:

- HTTPS server with automatic SSL certificate management
- SSL certificates downloaded automatically from E-Hentai servers
- Secure server communication using HTTPS
- Streamlined cache management
- Removed GUI components
- Maintained core protocol compatibility

## File Structure

```
hath/
├── base/
│   ├── __init__.py
│   ├── hentai_at_home_client.py    # Main client class
│   ├── settings.py                 # Configuration management
│   ├── out.py                      # Logging system
│   ├── cache_handler.py            # File cache management
│   ├── http_server.py              # HTTP server implementation
│   ├── server_handler.py           # Server communication
│   ├── input_query_handler_cli.py  # CLI input handling
│   └── tools.py                    # Utility functions
└── main.py                         # Entry point
```
## Security Features

- **HTTPS Server**: All cached files are served over HTTPS using certificates from E-Hentai
- **Certificate Management**: SSL certificates are automatically downloaded and refreshed
- **Secure Communication**: All server communication uses HTTPS with proper certificate validation
- **File Integrity**: SHA1 verification ensures cached files are not corrupted
- **Access Control**: Built-in flood control and request validation

## License

GNU General Public License v3 - same as the original Java implementation.

## Contributing

This is a faithful port of the original Java client. Changes should maintain compatibility with the Hentai@Home network protocol.

## Disclaimer

This software comes with ABSOLUTELY NO WARRANTY. Use at your own risk.
