# Multiprocess Mode Documentation

## Overview

The py-hath client now supports multiprocess mode for enhanced performance and reliability. This document explains the multiprocess architecture, benefits, and usage.

## Architecture

### Process Structure
```
┌─────────────────┐    ┌─────────────────┐
│   Main Process  │    │  HTTP Process   │
│                 │    │                 │
│ • Client Control│◄──►│ • File Serving  │
│ • Settings Mgmt │    │ • Range Requests│
│ • Stats Collect │    │ • Session Mgmt  │
│ • RPC Handling  │    │ • Bandwidth     │
│ • Download Mgmt │    │                 │
└─────────────────┘    └─────────────────┘
         │                       │
         └─── Shared Memory & Queues ───┘
```

### Components

#### Main Process
- **Client Control**: Overall client lifecycle management
- **Settings Management**: Configuration and server communication
- **Statistics Collection**: Aggregates stats from all processes
- **RPC Handling**: Server commands and status reporting
- **Process Monitoring**: Health checks and restart management
- **Download Management**: Handles gallery downloads and file fetching

#### HTTP Process
- **File Serving**: Serves cached files to clients with HTTPS
- **Range Requests**: Supports partial content (HTTP 206)
- **Session Management**: Tracks client connections and bandwidth
- **Content Delivery**: Optimized file streaming with throttling

### Shared Resources

#### Shared Memory
- **Cache Index**: File ID to metadata mapping
- **Configuration**: Client settings and server data
- **Statistics**: Performance metrics and counters

#### Message Queues
- **Stats Queue**: Performance data from all processes
- **Download Queue**: Download requests for background processing
- **Command Queue**: Control commands between processes
- **Response Queue**: Command responses and status updates

## Benefits

### Performance Benefits
- ✅ **HTTP Parallelism**: Multiple concurrent request handling
- ✅ **Process Isolation**: HTTP server crashes don't affect main client
- ✅ **Better Resource Usage**: Separate processes for I/O vs computation
- ✅ **Scalability**: Handle more concurrent file serving requests
- ✅ **GIL Bypass**: HTTP serving benefits from true parallelism

### Reliability Benefits
- ✅ **Fault Isolation**: HTTP server crash won't affect main client functions
- ✅ **Process Recovery**: Automatic restart of failed HTTP server
- ✅ **Resource Management**: Better control over HTTP serving resources

### Security Features
- ✅ **Full SSL/TLS Support**: HTTPS server with automatic certificate management
- ✅ **Client Authentication**: PKCS#12 certificate loading and validation
- ✅ **Modern Encryption**: TLS 1.2+ with secure cipher suites (ECDHE+AESGCM, CHACHA20)
- ✅ **Certificate Auto-Download**: Automatic certificate refresh from H@H servers
- ✅ **Process Isolation**: Security boundaries between processes
- ✅ **Validated Downloads**: SHA1 hash verification for all files

*The multiprocess implementation maintains the same security level as single-process mode.*
- ✅ **Graceful Degradation**: System continues if one process fails

### Operational Benefits
- ✅ **Monitoring**: Per-process resource tracking
- ✅ **Hot Reloading**: Restart components without full shutdown
- ✅ **Load Distribution**: Multiple worker processes
- ✅ **Debug Isolation**: Issues contained to specific processes

## Usage

### Starting Multiprocess Mode

#### Using the Main Script
```bash
# Basic multiprocess mode
./main.py --multiprocess

# With custom worker count
./main.py --mp --workers 8

# With debug logging
./main.py --multiprocess --debug

# Help and options
./main.py --help
```

#### Direct Python Invocation
```bash
# Direct invocation
python main.py --multiprocess

# Short form
python main.py --mp
```

### Configuration

#### Multiprocess Settings
Edit `hath/base/multiprocess_config.py`:

```python
class MultiprocessConfig:
    HTTP_WORKERS = 4                    # HTTP server processes
    DOWNLOAD_WORKERS = 2               # Download manager processes
    MAX_CONCURRENT_DOWNLOADS = 4      # Downloads per manager
    
    STATS_QUEUE_SIZE = 1000           # Statistics buffer
    HEARTBEAT_INTERVAL = 10           # Health check frequency
    MAX_RESTART_ATTEMPTS = 3          # Process restart limits
```

#### Runtime Configuration
```bash
# Custom worker counts
./main.py --mp --workers 8

# Custom port
./main.py --mp --port 8080

# Custom cache directory
./main.py --mp --cache-dir /path/to/cache
```

## Monitoring

### Process Health
The main process monitors worker health via:
- **Heartbeat Messages**: Every 10 seconds
- **Queue Status**: Message queue depths
- **Resource Usage**: Memory and CPU tracking
- **Error Reporting**: Exception handling and logging

### Logging
Each process maintains separate logs:
- `log_main_YYYYMMDD_HHMMSS.txt` - Main process
- `log_http_server_YYYYMMDD_HHMMSS.txt` - HTTP server
- `log_download_manager_YYYYMMDD_HHMMSS.txt` - Download manager

### Statistics
Enhanced statistics tracking:
- Per-process performance metrics
- Queue depth monitoring
- Inter-process communication stats
- Cache synchronization status

## Comparison: Single vs Multiprocess

| Feature | Single Process | Multiprocess |
|---------|---------------|-------------|
| **CPU Usage** | Limited by GIL | Full multi-core |
| **Memory** | Lower overhead | Higher overhead |
| **Fault Tolerance** | Single point of failure | Isolated failures |
| **Startup Time** | Faster | Slower |
| **Debugging** | Simpler | More complex |
| **Performance** | Good for low traffic | Excellent for high traffic |
| **Scalability** | Limited | High |
| **Resource Control** | Basic | Advanced |

## Best Practices

### When to Use Multiprocess Mode
- ✅ High-traffic H@H nodes (>100 concurrent connections)
- ✅ Multi-core servers with ample RAM
- ✅ Nodes requiring maximum reliability
- ✅ Heavy gallery download usage
- ✅ Production environments

### When to Use Single Process Mode
- ✅ Low-traffic nodes (<50 concurrent connections)
- ✅ Limited RAM systems (<4GB)
- ✅ Development and testing
- ✅ Simple deployments
- ✅ Debugging scenarios

### Performance Tuning
1. **Worker Count**: Start with CPU core count
2. **Queue Sizes**: Increase for high-load scenarios
3. **Heartbeat Interval**: Reduce for faster failure detection
4. **Memory Limits**: Set appropriate shared memory size

### Troubleshooting
1. **Check Logs**: Each process has separate log files
2. **Monitor Queues**: Watch for queue overflow
3. **Resource Usage**: Monitor CPU and memory per process
4. **Process Health**: Check heartbeat status

## Migration Path

### Gradual Adoption
1. **Test Environment**: Start with `--debug` mode
2. **Low Traffic**: Test during low-usage periods
3. **Monitor Performance**: Compare metrics with single-process
4. **Tune Configuration**: Adjust worker counts and queue sizes
5. **Full Production**: Deploy when satisfied with performance

### Rollback Plan
Simply restart without `--multiprocess` flag to return to single-process mode. All configuration and cache data remains compatible.

## Future Enhancements

### Planned Features
- **Auto-scaling**: Dynamic worker count based on load
- **Load Balancing**: Advanced request distribution
- **Hot Configuration**: Runtime setting changes
- **Advanced Monitoring**: Web-based process dashboard
- **Cluster Mode**: Multiple machine coordination

### Performance Targets
- **2-4x HTTP Throughput**: With multiple HTTP workers
- **50% Faster Downloads**: With dedicated download processes
- **Better Memory Efficiency**: With process isolation
- **Reduced Latency**: For concurrent operations
