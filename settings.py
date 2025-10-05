## Hentai@Home Python Client Sttings

# The number of gunicorn workers, default is 4
workers = 4

# zip the gallery downloaded from downloader?
zip_downloaded = True

# data directory for ssl certificates, login file, and database
data_dir = 'data'

# cache directory to save cached image
cache_dir = 'cache'

# log directory for application logs
log_dir = 'log'

# log level (INFO, DEBUG, WARNING, or ERROR)
# will override setting from client page
#log_level = ''

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