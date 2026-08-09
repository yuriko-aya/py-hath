## Hentai@Home Python Client Settings

# Client version is defined in hath/constants.py (CLIENT_VERSION)

# The number of gunicorn worker processes (use fewer with gevent)
workers = 2

# Gunicorn worker class: "sync" or "gevent" (recommended for public HTTPS nodes)
worker_class = "gevent"

# Concurrent connections per gevent worker (ignored for sync workers)
worker_connections = 1000

# zip the gallery downloaded from downloader?
zip_downloaded = True

# data directory for ssl certificates, login file, and database
data_dir = 'data'

# cache directory to save cached image
cache_dir = 'cache'

# download directory for gallery downloads
download_dir = 'download'

# runtime config cache directory (config.json for worker processes)
config_dir = 'config'

# log directory for application logs
log_dir = 'log'

# log level (INFO, DEBUG, WARNING, or ERROR)
# will override setting from client page
#log_level = ''

# JSON structured logs for production aggregation (default: False)
json_logs = False

# Trust X-Forwarded-For for servercmd IP checks (only enable behind a trusted reverse proxy)
trust_x_forwarded_for = False

# hath override port
# this will override setting from client page
#hath_port = 443

# use hath override port
# set True if you use hath override port above
override_port = False

# disable ip check
# do check source IP address, could be dangerous
# normally only IP in the RPC IP list are allowed to send servercmd
# needed when using NAT
disable_ip_check = False

# download proxy
# proxy used for dowloading files from main server
# format: 'scheme://user:password@host:port' or 'scheme://host:port'
#download_proxy = 'socks5://user:password@127.0.0.1:1080'

# rpc proxy
# proxy used for rpc requests
# format: 'scheme://user:password@host:port' or 'scheme://host:port'
#rpc_proxy = 'socks5://user:password@127.0.0.1:1080'
