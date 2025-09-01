# Hentai@Home Python Client

A robust Python implementation of a Hentai@Home client that provides high-performance image caching and serving capabilities.

## Features

### Core Functionality
- **Flask-based Web Server**: High-performance image serving with multi-threaded request handling
- **SSL/TLS Security**: Full PKCS#12 certificate support with automatic certificate management
- **Advanced Caching**: Intelligent cache validation and cleanup
- **Server Communication**: Real-time synchronization with H@H network servers
- **Background Task Management**: Automated background processes with locking

### Advanced Features
- **Automatic Cache Validation**: Validates cache integrity against static ranges
- **Configuration Caching**: Persistent configuration storage with JSON caching
- **Graceful Shutdown**: Proper cleanup and notification on exit
- **Comprehensive Logging**: Structured logging with rotation and multiple log levels

## Prerequisites

- **Python**: 3.8 or higher
- **System**: Linux/Unix recommended (tested on Linux)
- **Prerequisites**: Valid Hentai@Home client ID and key (will be prompted on first run)
- **Certificates**: SSL certificates are automatically downloaded from the H@H servers
- **Network**: Stable internet connection with appropriate firewall configuration

## Installation

## Quick Start

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the Application**:
   ```bash
   python app.py
   ```

3. **Enter Credentials**: On first run, you'll be prompted to enter your H@H client ID and key

4. **Automatic Setup**: The application will automatically download certificates and configure itself

That's it! No manual file creation or certificate management required.

### Production Deployment
```bash
# Using Gunicorn (production)
python run_gunicorn.py
```

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

### Configuration Files
The following files are automatically managed:
- `.hath_config_cache.json` - Cached configuration data
- `.hath-background-tasks.lock` - Background task coordination
- `client_login.example` - Example credential file format

## Usage

### Development Mode
```bash
python app.py
```

### Production Mode
```bash
# Using Gunicorn (recommended for production)
python run_gunicorn.py
```

### Environment Variables
```bash
export FLASK_ENV=production  # For production deployment
export HATH_DEBUG=1         # Enable debug logging
```

## Directory Structure

```
py-hath/
├── app.py                    # Main Flask application
├── hath_config.py           # Configuration management
├── run_gunicorn.py          # Gunicorn production server
├── wsgi.py                  # WSGI entry point
├── requirements.txt         # Python dependencies
├── .gitignore              # Git ignore rules
├── data/                   # Configuration and certificates
│   ├── client_login        # Client credentials (auto-created on first run)
│   ├── client_login.example # Example credentials file
│   ├── client.crt          # SSL certificate (auto-downloaded)
│   ├── client.key          # SSL private key (auto-generated)
│   ├── client.p12          # PKCS#12 bundle (auto-downloaded)
│   ├── .hath_config_cache.json # Configuration cache
│   └── .hath-background-tasks.lock # Task coordination
├── cache/                  # Image cache storage
│   └── [xx]/               # Organized by hash prefix (e.g., 6a/, 6b/, etc.)
├── log/                    # Application logs
│   ├── hath_client.log     # General application logs
│   ├── hath_errors.log     # Error logs
│   ├── hath_access.log     # HTTP access logs
│   ├── gunicorn_access.log # Gunicorn access logs
│   └── gunicorn_error.log  # Gunicorn error logs
└── env/                    # Virtual environment
```

## API Endpoints

### Core Endpoints
- `GET /` - Health check and server status
- `POST /servercmd/<command>/<additional>/<time>/<key>` - Server command interface
- `GET /h/<fileid>/<additional>/<filename>` - Image serving endpoint

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

### Cache Management
- **Automatic Validation**: Validates cache files against static ranges
- **Cleanup Operations**: Automatic removal of invalid files
- **Hash-based Organization**: Files organized by hash prefix for efficient lookup

### Performance Optimizations
- Multi-threaded request handling
- Efficient file serving with proper headers
- Connection pooling for server communication
- Configuration caching for improved startup times

## Monitoring and Health Checks

### Built-in Monitoring
- Server connectivity checks
- Cache integrity validation
- SSL certificate status monitoring
- Background task coordination

## Troubleshooting

### Common Issues
1. **SSL Certificate Problems**: Certificates are automatically downloaded - check network connectivity if issues occur
2. **Cache Validation Errors**: Check static range configuration and file permissions
3. **Server Connection Issues**: Verify network connectivity and firewall settings
4. **Background Task Conflicts**: Check for `.hath-background-tasks.lock` file

### Debug Mode
Enable debug logging:
```bash
export HATH_DEBUG=1
python app.py
```

## Development

### Code Structure
- **app.py**: Main Flask application with routing and request handling
- **hath_config.py**: Configuration management and server communication
- **run_gunicorn.py**: Production server configuration
- **wsgi.py**: WSGI application interface

### Key Functions
- Cache validation and cleanup
- SSL certificate management
- Background task coordination
- Server command processing

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
