# Hentai@Home Python Client

A robust, modular Python implementation of a Hentai@Home client that provides high-performance image caching and serving capabilities with enterprise-grade architecture.

## Features

### Core Functionality
- **Modular Architecture**: Clean separation of concerns with dedicated managers for different functionalities
- **Flask-based Web Server**: High-performance image serving with multi-threaded request handling
- **SSL/TLS Security**: Full PKCS#12 certificate support with automatic certificate management
- **SQLite Database**: Persistent cache management with WAL mode for high concurrency
- **Advanced Caching**: Intelligent cache validation, cleanup, and hash-based organization
- **Server Communication**: Real-time synchronization with H@H network servers via RPC
- **Background Task Management**: Automated background processes with proper coordination

### Advanced Features
- **Database-Driven Cache**: SQLite-based cache management with transaction safety
- **Download Manager**: Automated gallery downloading with ZIP compression and retry logic
- **Event System**: Centralized event management for coordinated operations
- **Configuration Singleton**: Thread-safe configuration management across workers
- **Verification System**: Automated cache integrity verification
- **Storage Management**: Intelligent storage allocation and cleanup
- **Comprehensive Logging**: Structured logging with rotation and multiple log levels
- **Production Ready**: Gunicorn integration with proper worker coordination

## Prerequisites

- **Python**: 3.8 or higher
- **System**: Linux/Unix recommended (tested on Linux)
- **Database**: SQLite 3.7+ (for WAL mode support)
- **Prerequisites**: Valid Hentai@Home client ID and key (will be prompted on first run)
- **Certificates**: SSL certificates are automatically downloaded from the H@H servers
- **Network**: Stable internet connection with appropriate firewall configuration

## Installation

### Quick Start

1. **Clone or Download**: Get the project files to your desired directory

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Application**:
   ```bash
   # Development mode
   python run_gunicorn.py
   
   # Or using the WSGI application directly
   python wsgi.py
   ```

4. **Enter Credentials**: On first run, you'll be prompted to enter your H@H client ID and key

5. **Automatic Setup**: The application will automatically:
   - Download and configure SSL certificates
   - Initialize the SQLite database
   - Set up cache directories
   - Configure logging

That's it! No manual file creation or certificate management required.

### Dependencies
The application requires the following Python packages:

```
Flask>=2.3.0          # Web framework
requests>=2.31.0      # HTTP client for server communication
cryptography>=41.0.0  # SSL/TLS and certificate handling
waitress>=2.1.0       # Alternative WSGI server
gunicorn>=21.2.0      # Production WSGI server (recommended)
watchdog>=3.0.0       # File system monitoring
gevent==25.8.2        # Asynchronous networking library
```

All dependencies are automatically installed via `pip install -r requirements.txt`.

### Production Deployment
```bash
# Recommended: Using Gunicorn (production-ready)
python run_gunicorn.py

# Alternative: Direct WSGI execution
python wsgi.py
```

## Architecture

### Modular Design
The application follows a clean, modular architecture with dedicated managers:

- **`app_manager.py`**: Flask application factory and routing logic
- **`background_manager.py`**: Background task coordination and execution
- **`cache_manager.py`**: Cache operations and file management
- **`config_singleton.py`**: Thread-safe configuration management
- **`db_manager.py`**: SQLite database operations with connection pooling
- **`download_manager.py`**: Gallery download management with automatic ZIP compression
- **`event_manager.py`**: Centralized event system for component coordination
- **`log_manager.py`**: Logging configuration and management
- **`rpc_manager.py`**: Server communication and RPC handling
- **`storage_manager.py`**: Storage allocation and cleanup operations
- **`verification_manager.py`**: Cache integrity verification

### Database Architecture
- **SQLite with WAL mode**: High-concurrency database operations
- **Connection pooling**: Thread-local connections for performance
- **Transaction safety**: ACID compliance for cache operations
- **Schema management**: Automatic database initialization and migrations

## Configuration

### Client Credentials
On first run, the application will prompt you to enter your Hentai@Home credentials:
- **Client ID**: Your H@H client identifier (numeric)
- **Client Key**: Your H@H client key

The credentials will be automatically saved to `data/client_login` for future use.

Alternatively, you can manually create the `data/client_login` file with the format:
```
client_id-client_key
```
Example: `12345-abcdef123456789`

### SSL Certificates
SSL certificates are automatically downloaded and managed by the application:
- `client.crt` - SSL certificate (auto-downloaded)
- `client.key` - SSL private key (auto-generated)  
- `client.p12` - PKCS#12 bundle (auto-downloaded and converted)

### Database Configuration
The application uses SQLite for persistent storage:
- `pcache.db` - Main database file
- `pcache.db-shm` - Shared memory file (WAL mode)
- `pcache.db-wal` - Write-ahead log file (WAL mode)

### Configuration Files
The following files are automatically managed:
- `.hath_config_cache.json` - Cached configuration data
- `.hath-background-tasks.lock` - Background task coordination
- `client_login.example` - Example credential file format

## Usage

### Development Mode
```bash
# Run with Gunicorn (recommended)
python run_gunicorn.py

# Direct WSGI execution
python wsgi.py
```

### Production Mode
```bash
# Production deployment with Gunicorn
python run_gunicorn.py

# The application will automatically:
# - Initialize the database
# - Set up logging
# - Configure worker coordination
# - Handle SSL certificates
```

### Testing and Maintenance
```bash
# Test database connectivity
python test_check_db.py

# Check application status
curl https://localhost:your_port/
```

### Environment Variables
```bash
export FLASK_ENV=production  # For production deployment
export HATH_DEBUG=1         # Enable debug logging
```

## Directory Structure

```
py-hath/
├── app_manager.py           # Flask application factory and routing
├── background_manager.py    # Background task coordination
├── cache_manager.py         # Cache operations and file management
├── config_singleton.py      # Thread-safe configuration management
├── db_manager.py           # SQLite database operations
├── download_manager.py     # Gallery download management with ZIP compression
├── event_manager.py        # Centralized event system
├── hath_config.py          # Configuration loading and server communication
├── log_manager.py          # Logging configuration
├── rpc_manager.py          # Server RPC communication
├── storage_manager.py      # Storage allocation and cleanup
├── verification_manager.py # Cache integrity verification
├── zip_compressor.py       # ZIP compression utility for gallery downloads
├── run_gunicorn.py         # Gunicorn production server launcher
├── wsgi.py                 # WSGI application entry point
├── gunicorn.conf.py        # Gunicorn configuration
├── test_check_db.py        # Database connectivity test
├── requirements.txt        # Python dependencies
├── LICENSE                 # GPLv3 license
├── .gitignore             # Git ignore rules
├── data/                  # Configuration and certificates
│   ├── client_login       # Client credentials (auto-created)
│   ├── client_login.example # Example credentials file
│   ├── client.crt         # SSL certificate (auto-downloaded)
│   ├── client.key         # SSL private key (auto-generated)
│   ├── client.p12         # PKCS#12 bundle (auto-downloaded)
│   ├── pcache.db          # SQLite database (auto-created)
│   ├── pcache.db-shm      # SQLite shared memory (WAL mode)
│   ├── pcache.db-wal      # SQLite write-ahead log (WAL mode)
│   └── .hath_config_cache.json # Configuration cache
├── cache/                 # Image cache storage
│   └── [xx]/              # Hash-organized directories (e.g., 6a/, 6b/, etc.)
│       └── [xx]/          # Secondary hash level
│           └── [files]    # Cached image files
├── download/              # Gallery downloads and ZIP archives
│   ├── [Gallery Name [ID-Resolution]]/  # Downloaded gallery directories
│   └── [Gallery Name [ID-Resolution]].zip  # Compressed gallery archives
├── log/                   # Application logs
│   ├── hath_client.log    # General application logs
│   ├── hath_errors.log    # Error logs
│   ├── hath_access.log    # HTTP access logs
│   ├── gunicorn_access.log # Gunicorn access logs
│   └── gunicorn_error.log # Gunicorn error logs
└── env/                   # Virtual environment (if using venv)
    ├── bin/               # Executables
    ├── lib/               # Python packages
    └── include/           # Header files
```

## API Endpoints

### Core Endpoints
- `GET /` - Health check and server status
- `POST /servercmd/<command>/<additional>/<time>/<key>` - Server command interface
- `GET /h/<fileid>/<additional>/<filename>` - Image serving endpoint

## Download Manager

The download manager provides automated gallery downloading capabilities for the H@H client. It operates as a background service that can be triggered via server commands.

### Features
- **Automated Gallery Downloads**: Continuously processes download queues from the H@H server
- **Multi-file Support**: Downloads complete galleries with all associated files
- **Hash Verification**: SHA1 hash validation for file integrity
- **Retry Logic**: Automatic retry with multiple download mirrors
- **ZIP Compression**: Individual gallery compression with automatic cleanup
- **Background Processing**: Non-blocking operation via separate threads and processes

### How It Works
1. **Queue Fetching**: Retrieves pending downloads from the H@H server
2. **Metadata Parsing**: Extracts gallery information and file lists
3. **File Downloads**: Downloads each file with hash verification and retry logic
4. **ZIP Creation**: Compresses completed galleries using `zip_compressor.py`
5. **Cleanup**: Removes original directories after successful compression
6. **Progress Tracking**: Marks galleries as downloaded to avoid reprocessing

### Server Commands
The download manager is triggered via the `start_downloader` server command:
- Server sends command to `/servercmd/start_downloader/<timestamp>/<key>`
- Download manager starts in background thread
- Processes all pending downloads until queue is empty

### Files and Structure
- **`download_manager.py`**: Main download logic and queue processing
- **`zip_compressor.py`**: Individual gallery ZIP compression utility
- **`download/`**: Download directory for gallery files and ZIP archives

### Configuration
The download manager uses the existing H@H configuration:
- Client ID and key for server authentication
- Download directory path (defaults to `download/`)
- Retry logic and timeout settings
- Logging configuration

### Monitoring
Download progress is logged to the standard application logs:
- Gallery download start/completion events
- File download progress and errors
- ZIP compression status
- Server communication events

## Logging

The application maintains comprehensive logs in the `log/` directory:

### Log Files
- **hath_client.log**: General application events and operations
- **hath_errors.log**: Errors, warnings, and critical issues
- **hath_access.log**: HTTP request access logs
- **gunicorn_access.log**: Gunicorn server access logs (production)
- **gunicorn_error.log**: Gunicorn server error logs (production)

### Log Features
- Daily log rotation with automatic archiving
- Configurable log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Structured logging format with timestamps
- Separate error tracking for debugging

## Performance Features

### Database-Driven Cache Management
- **SQLite with WAL Mode**: High-concurrency database operations
- **Connection Pooling**: Thread-local connections for optimal performance
- **Transaction Safety**: ACID compliance for all cache operations
- **Automatic Cleanup**: Scheduled cleanup of invalid and expired files
- **Hash-based Organization**: Two-level hash directory structure for efficient file lookup

### Advanced Caching
- **Integrity Verification**: Automatic validation of cached files
- **Storage Management**: Intelligent disk space allocation and monitoring
- **Concurrent Access**: Multi-threaded file serving with proper locking
- **Event-Driven Updates**: Real-time cache updates based on server events

### Performance Optimizations
- **Multi-process Architecture**: Gunicorn worker processes for scalability
- **Efficient File Serving**: Direct file serving with proper HTTP headers
- **Connection Pooling**: Persistent connections for server communication
- **Configuration Caching**: Singleton pattern for configuration access
- **Background Processing**: Non-blocking background tasks for maintenance

## Monitoring and Health Checks

### Built-in Monitoring
- **Database Health**: Connection status and transaction monitoring
- **Cache Integrity**: Automated verification of cached files
- **Server Connectivity**: Regular heartbeat checks with H@H servers
- **SSL Certificate Status**: Automatic certificate validation and renewal
- **Background Task Coordination**: Multi-process task synchronization
- **Storage Monitoring**: Disk space utilization tracking

### Health Check Endpoints
- `GET /` - Basic health check and server status
- Database connectivity test available via `test_check_db.py`

### Event System
- Centralized event management for component coordination
- Real-time status updates across managers
- Automatic error recovery and notification

## Troubleshooting

### Common Issues

1. **Database Connection Problems**: 
   - Run `python test_check_db.py` to verify database connectivity
   - Check file permissions on `data/pcache.db*` files
   - Ensure WAL mode is supported (SQLite 3.7+)

2. **SSL Certificate Problems**: 
   - Certificates are automatically downloaded - check network connectivity
   - Verify `data/` directory permissions
   - Check firewall settings for HTTPS connections

3. **Cache Validation Errors**: 
   - Run verification manager to check cache integrity
   - Check static range configuration in logs
   - Verify file permissions on cache directories

4. **Server Connection Issues**: 
   - Verify network connectivity and firewall settings
   - Check client credentials in `data/client_login`
   - Monitor RPC communication in logs

5. **Background Task Conflicts**: 
   - Check for stale lock files
   - Verify proper shutdown of previous instances
   - Monitor event manager coordination

### Debug Mode
Enable comprehensive debug logging:
```bash
export HATH_DEBUG=1
python run_gunicorn.py
```

### Database Troubleshooting
```bash
# Test database connectivity
python test_check_db.py

# Check database integrity (if needed)
sqlite3 data/pcache.db "PRAGMA integrity_check;"
```

## Development

### Architecture Overview
The application follows a modular architecture with clear separation of concerns:

### Core Modules
- **`app_manager.py`**: Flask application factory with routing and request handling
- **`config_singleton.py`**: Thread-safe configuration management using singleton pattern
- **`db_manager.py`**: SQLite database operations with connection pooling and WAL mode
- **`hath_config.py`**: Configuration loading, validation, and server communication

### Manager Modules
- **`background_manager.py`**: Coordinates background tasks and worker processes
- **`cache_manager.py`**: Handles cache operations, file management, and cleanup
- **`download_manager.py`**: Manages gallery downloads, ZIP compression, and queue processing
- **`event_manager.py`**: Centralized event system for inter-component communication
- **`log_manager.py`**: Logging configuration with file rotation and structured output
- **`rpc_manager.py`**: Server communication, RPC calls, and protocol handling
- **`storage_manager.py`**: Storage allocation, monitoring, and cleanup operations
- **`verification_manager.py`**: Cache integrity verification and validation

### Key Features
- **Thread Safety**: All managers are designed for multi-threaded operation
- **Database Integration**: Persistent storage with ACID compliance
- **Event-Driven Architecture**: Loose coupling through centralized event system
- **Configuration Management**: Singleton pattern with automatic reloading
- **Error Handling**: Comprehensive error handling and recovery mechanisms

### Development Setup
```bash
# Clone the repository
git clone <repository-url>
cd py-hath

# Set up virtual environment (recommended)
python -m venv env
source env/bin/activate  # On Windows: env\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run in development mode
python run_gunicorn.py
```

## Security

### Features
- SSL/TLS encryption for all communications
- PKCS#12 certificate support
- Secure key management
- Request validation and authentication
- Protected server command interface

### Best Practices
- Keep client credentials secure and up-to-date
- Monitor logs for suspicious activity
- Use production servers (Gunicorn) for deployment
- Implement proper firewall rules
- Certificates are automatically managed - no manual intervention needed

## License

This project is licensed under the GNU General Public License v3.0 (GPLv3). See the [LICENSE](LICENSE) file for the full license text.

### What this means:
- You are free to use, modify, and distribute this software
- Any modifications or derivative works must also be licensed under GPLv3
- You must include the license and copyright notice with any distribution
- There is no warranty provided with this software

Users are responsible for compliance with all applicable terms of service and legal requirements.

## Contributing

This is an independent implementation. For improvements and bug reports, please follow standard GitHub contribution practices.

## Support

This is an independent implementation. For official Hentai@Home support, please refer to the official Hentai@Home documentation and community resources.

For issues specific to this Python implementation, please check the logs and ensure proper configuration before seeking assistance.
