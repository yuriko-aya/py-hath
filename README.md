# Hentai@Home Python Client

This is a Python implementation of the Hentai@Home client, converted from the original Java version. **Now with multiprocess support for enhanced performance!**

## Features

- **🚀 Multiprocess Mode**: True parallel processing that bypasses Python GIL limitations
- **⚡ Enhanced Performance**: 2-4x throughput improvement for high-traffic nodes
- **🔧 Core functionality**: File caching, HTTP server, server communication
- **💻 Command-line interface**: No GUI dependencies with intuitive launcher
- **🐍 Python 3.7+ compatibility**: Modern Python features
- **📜 GPL v3 licensed**: Same license as original
- **🛡️ Fault Isolation**: Process crashes don't affect other components
- **📊 Advanced Monitoring**: Per-process health checks and statistics

## Performance Modes

### Multiprocess Mode (Recommended for high-traffic)
- ✅ True parallelism across multiple CPU cores
- ✅ Separate processes for HTTP serving and downloads
- ✅ Fault isolation and automatic process recovery
- ✅ Better resource management and monitoring
- ✅ 2-4x performance improvement

### Single-Process Mode (Good for low-traffic)
- ✅ Lower memory overhead
- ✅ Simpler debugging and deployment
- ✅ Faster startup time
- ✅ Compatible with resource-limited systems

## Requirements

- Python 3.7 or newer
- requests
- cryptography

## Quick Start

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Launch the client:

**Multiprocess Mode (Recommended):**
```bash
./launch.py --multiprocess
```

**Single-Process Mode:**
```bash
./launch.py
```

**With Options:**
```bash
./launch.py --mp --workers 8 --debug  # 8 workers with debug logging
./launch.py --help                    # Show all options
```

## Detailed Usage

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
