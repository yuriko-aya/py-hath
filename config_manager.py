import os
import time
import hashlib
import ipaddress
import json
import rpc_manager
import settings
import psutil
import socket

from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from typing import Dict, Optional, Tuple, Any, List
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Config:
    data_dir = ''
    cache_dir = ''
    log_dir = ''
    override_port = False
    hath_port = 443
    zip_downloaded = True
    log_overrided = False
    override_level = 'DEBUG'
    is_server_ready = False
    disable_ip_check = False
    download_proxy = ''
    rpc_proxy = ''

    # Client credentials and configuration
    client_id = ''
    client_key = ''
    server_time = 0
    time_difference = 0
    config = {}
    cert_file = ''
    key_file = ''
    client_build: str = "176"  # Fixed client build version

    # RPC server IP list for failover (converted to standard IPv4 format)
    rpc_server_ips: list = []
    rpc_fallback_domain: str = "rpc.hentaiathome.net"

    # Static range
    static_range_count: Optional[int] = None
    static_range: list = []

def get_local_ips():
    ips = []
    for ifname, addrs in psutil.net_if_addrs().items():
        if ifname == "lo":
            continue
        for a in addrs:
            if a.family in (socket.AF_INET, socket.AF_INET6):
                if a.address.startswith("127.") or a.address == "::1":
                    continue
                ips.append(a.address)
    return ips

def _convert_ipv6_mapped_to_ipv4(ip_list: List[str]) -> List[str]:
    """Convert IPv6-mapped IPv4 addresses to standard IPv4 format.
    
    Args:
        ip_list: List of IP addresses (may include IPv6-mapped IPv4)
        
    Returns:
        List of converted IPv4 addresses
    """
    converted_ips = []
    
    for ip_str in ip_list:
        try:
            # Parse the IP address
            ip_addr = ipaddress.ip_address(ip_str)
            
            # Check if it's IPv6-mapped IPv4
            if ip_addr.version == 6 and ip_addr.ipv4_mapped:
                # Convert to IPv4
                ipv4_addr = str(ip_addr.ipv4_mapped)
                converted_ips.append(ipv4_addr)
            elif ip_addr.version == 4:
                # Already IPv4
                converted_ips.append(ip_str)
                logger.debug(f"Using IPv4 address: {ip_str}")
            else:
                # Regular IPv6, keep as-is but warn
                converted_ips.append(ip_str)
                logger.warning(f"Regular IPv6 address detected: {ip_str}")
                
        except (ipaddress.AddressValueError, ValueError) as e:
            logger.error(f"Invalid IP address format: {ip_str}, skipping - {e}")
            continue
    logger.debug(f"RPC server IPs: {converted_ips}")
    return converted_ips


def read_client_credentials(data_dir) -> bool:
    """Read client_id and client_key from data/client_login file."""
    client_login_path = os.path.join(data_dir, "client_login")

    try:
        with open(client_login_path, 'r') as f:
            content = f.read().strip()
            
        if '-' in content:
            client_id, client_key = content.split('-', 1)
            logger.info(f"Loaded client credentials: ID={client_id}")
            Config.client_id = client_id
            Config.client_key = client_key
            return True
        else:
            logger.error("Invalid format in client_login file. Expected 'id-key' format.")
            return False
            
    except FileNotFoundError:
        logger.warning(f"client_login file not found in {data_dir} directory")
        logger.info("Please enter your Hentai@Home client credentials:")
        
        try:
            client_id = input("Client ID: ").strip()
            client_key = input("Client Key: ").strip()
            
            if not client_id or not client_key:
                logger.error("Client ID and Client Key cannot be empty")
                return False
            
            # Validate client_id is numeric
            try:
                int(client_id)
            except ValueError:
                logger.error("Client ID must be numeric")
                return False
            
            # Save credentials to file
            credentials_content = f"{client_id}-{client_key}"
            with open(client_login_path, 'w') as f:
                f.write(credentials_content)
            
            logger.info(f"Credentials saved to {client_login_path}")
            
            # Set the credentials
            client_id = client_id
            client_key = client_key
            
            logger.info(f"Loaded client credentials: ID={client_id}")
            return True
            
        except KeyboardInterrupt:
            logger.error("User cancelled credential input")
            return False
        except Exception as e:
            logger.error(f"Error saving credentials: {e}")
            return False
            
    except Exception as e:
        logger.error(f"Error reading client credentials: {e}")
        return False

def get_server_time() -> bool:
    """Get server time from remote server."""
    try:
        local_time_before = int(time.time())
        url_path = f'/15/rpc?clientbuild={Config.client_build}&act=server_stat'
        response = rpc_manager._make_rpc_request(url_path, timeout=10)
        
        # Parse key=value format
        for line in response.text.strip().split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                if key.strip() == 'server_time':
                    server_time = int(value.strip())
                    # Calculate time difference: server_time - local_time
                    time_difference = server_time - local_time_before
                    Config.server_time = server_time
                    logger.debug(f"Server time: {server_time}")
                    Config.time_difference = time_difference
                    logger.debug(f"Time difference: {time_difference} seconds")
                    return True
                    
        logger.error("server_time not found in response")
        return False
        
    except Exception as e:
        logger.error(f"Error getting server time: {e}")
        return False

def get_current_acttime() -> int:
    """Get current acttime (local time + time difference)."""
    current_local_time = int(time.time())
    return current_local_time + (Config.time_difference or 0)

def generate_actkey(act: str, add: str = "") -> str:
    """Generate actkey for authentication."""
    # actkey is SHA-1 hash of "hentai@home-{act}-{add}-{client_id}-{current_time}-{client_key}"
    current_acttime = get_current_acttime()
    data = f"hentai@home-{act}-{add}-{Config.client_id}-{current_acttime}-{Config.client_key}"
    return hashlib.sha1(data.encode()).hexdigest()

def get_client_config(force_refresh=False) -> bool:
    """Get client configuration from remote server."""
    try:
        current_acttime = get_current_acttime()
        if force_refresh:
            actkey = generate_actkey("client_settings")
            url_path = (f"/15/rpc?clientbuild={Config.client_build}&act=client_settings"
                    f"&cid={Config.client_id}&acttime={current_acttime}&actkey={actkey}")
        else:
            actkey = generate_actkey("client_login")
            url_path = (f"/15/rpc?clientbuild={Config.client_build}&act=client_login"
                    f"&cid={Config.client_id}&acttime={current_acttime}&actkey={actkey}")

        response = rpc_manager._make_rpc_request(url_path, timeout=10)

        response_text = response.text.strip()
        
        # Must have "OK" in response for success
        if "OK" not in response_text:
            logger.error(f"Server did not return OK status: {response_text}")
            return False

        # If disable_logging is set, but not in return, remove it from config
        if Config.config.get('disable_logging') and not 'disable_logging' in response_text:
            Config.config.pop('disable_logging', None)

        # Parse key=value format for successful responses
        for line in response_text.split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                # Handle rpc_server_ip specially
                if key == 'rpc_server_ip':
                    # Value is semicolon-separated list of IPv6-mapped IPv4 addresses
                    if value:
                        raw_ips = [ip.strip() for ip in value.split(';') if ip.strip()]
                        # Convert IPv6-mapped IPv4 to standard IPv4
                        Config.rpc_server_ips = _convert_ipv6_mapped_to_ipv4(raw_ips)
                    else:
                        logger.warning("Empty rpc_server_ip received")

                if key == 'static_ranges':
                    static_range = [sr for sr in value.split(';') if sr]
                    static_range_count = len(static_range)
                    Config.static_range = static_range
                    Config.static_range_count = static_range_count
                    logger.debug(f"Parsed {static_range_count} static ranges: {static_range}")
                
                if key == 'static_range_count':
                    static_range_count = int(value)
                    Config.static_range_count = static_range_count
                    logger.debug(f"Update static range count: {static_range_count}")

                Config.config[key] = value

        host = Config.config.get('host')
        local_ips = get_local_ips()
        if host not in local_ips:
            Config.config['host'] = '0.0.0.0'

        logger.info("Client configuration loaded successfully")
        logger.debug(f"Host: {Config.config.get('host')}")
        logger.debug(f"Port: {Config.config.get('port')}")
        if Config.rpc_server_ips:
            logger.debug(f"RPC servers: {Config.rpc_server_ips}")

        # Save configuration to cache file for worker processes
        save_config_cache()

        return True
        
    except Exception as e:
        logger.error(f"Error getting client config: {e}")
        return False

def save_config_cache() -> bool:
    """Save current configuration to cache file for worker processes."""
    try:
        cache_file = 'config/config.json'
        os.mkdir('config') if not os.path.exists('config') else None
        
        cache_data = {
            'client_id': Config.client_id,
            'client_key': Config.client_key,
            'config': dict(Config.config),
            'rpc_server_ips': list(Config.rpc_server_ips),
            'static_range': list(Config.static_range),
            'static_range_count': Config.static_range_count,
            'server_time': Config.server_time,
            'time_difference': Config.time_difference,
            'cert_file': Config.cert_file,
            'key_file': Config.key_file,
            'timestamp': time.time(),
            'log_dir': Config.log_dir,
            'log_overrided': Config.log_overrided,
            'override_level': Config.override_level,
            'disable_ip_check': Config.disable_ip_check,
            'download_proxy': Config.download_proxy,
            'rpc_proxy': Config.rpc_proxy,
        }
        
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f, indent=2)
        
        logger.debug(f"Configuration cached to {cache_file}")
        return True
        
    except Exception as e:
        logger.error(f"Error saving config cache: {e}")
        return False

def get_ssl_certificate(force_refresh: bool = False) -> bool:
    """Get SSL certificate from remote server.
    
    The certificate will be downloaded if:
    - No certificate exists
    - Existing certificate expires within 3 days
    - Existing certificate is more than one week old
    - force_refresh is True
    
    Args:
        force_refresh: If True, skip validity check and force download new certificate
    """
    # First check if existing certificate is still valid (unless force refresh)
    if not force_refresh and _check_certificate_validity():
        logger.debug("Using existing valid certificate")
        return True
    
    if force_refresh:
        logger.debug("Force refresh requested, downloading new certificate...")
    
    try:
        current_acttime = get_current_acttime()
        actkey = generate_actkey("get_cert")
        url_path = (f"/15/rpc?clientbuild={Config.client_build}&act=get_cert"
                    f"&add=&cid={Config.client_id}&acttime={current_acttime}&actkey={actkey}")
        
        logger.debug("Downloading new SSL certificate...")
        response = rpc_manager._make_rpc_request(url_path, timeout=30)
        
        # Save PKCS#12 certificate
        p12_path = os.path.join(Config.data_dir, "client.p12")
        with open(p12_path, 'wb') as f:
            f.write(response.content)
        
        # Convert PKCS#12 to separate cert and key files
        _convert_p12_to_pem(p12_path)
        
        logger.debug("SSL certificate downloaded and converted successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error getting SSL certificate: {e}")
        return False

def _convert_p12_to_pem(p12_path: str) -> None:
    """Convert PKCS#12 certificate to separate PEM files with full certificate chain."""
    try:
        with open(p12_path, 'rb') as f:
            p12_data = f.read()
        
        if not Config.client_key:
            raise ValueError("Client key is required for PKCS#12 conversion")
        
        # Load PKCS#12 with client_key as password
        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
            p12_data, Config.client_key.encode()
        )
        
        if not certificate:
            raise ValueError("No certificate found in PKCS#12 file")
        
        if not private_key:
            raise ValueError("No private key found in PKCS#12 file")
        
        # Save certificate with full chain
        cert_path = os.path.join(Config.data_dir, "client.crt")
        with open(cert_path, 'wb') as f:
            # Write the client certificate first
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
            
            # Write intermediate certificates to complete the chain
            if additional_certificates:
                logger.debug(f"Adding {len(additional_certificates)} intermediate certificates to chain")
                for intermediate_cert in additional_certificates:
                    f.write(intermediate_cert.public_bytes(serialization.Encoding.PEM))
            else:
                logger.warning("No intermediate certificates found in PKCS#12 file")
        
        Config.cert_file = cert_path
        
        # Save private key
        key_path = os.path.join(Config.data_dir, "client.key")
        with open(key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        Config.key_file = key_path

        logger.debug(f"Certificate saved to: {cert_path}")
        logger.debug(f"Private key saved to: {key_path}")
        
    except Exception as e:
        logger.error(f"Error converting PKCS#12 certificate: {e}")
        raise

def _check_certificate_validity() -> bool:
    """Check if existing certificate is valid and has more than 3 days until expiration,
    and is not more than one week old."""
    try:
        cert_path = os.path.join(Config.data_dir, "client.crt")
        key_path = os.path.join(Config.data_dir, "client.key")
        
        # Check if both files exist
        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            logger.debug("Certificate files not found")
            return False

        # Check certificate age (file modification time)
        cert_stat = os.stat(cert_path)
        cert_mtime = datetime.fromtimestamp(cert_stat.st_mtime)
        current_time = datetime.now()
        age_delta = current_time - cert_mtime
        
        logger.debug(f"Certificate file last modified: {cert_mtime}")
        logger.debug(f"Certificate age: {age_delta.days} days, {age_delta.seconds // 3600} hours")
        
        # If certificate is more than 7 days old, download new one
        if age_delta.days >= 7:
            logger.debug("Certificate is more than one week old, will download new one")
            return False
        
        # Read and parse the certificate
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        
        certificate = x509.load_pem_x509_certificate(cert_data)
        
        # Check expiration
        expiration_date = certificate.not_valid_after_utc
        current_date = datetime.now(timezone.utc)
        days_until_expiration = (expiration_date - current_date).days
        
        logger.debug(f"Certificate expires on: {expiration_date}")
        logger.debug(f"Days until expiration: {days_until_expiration}")
        
        if days_until_expiration > 3:
            logger.debug("Certificate is valid, not too old, and has more than 3 days until expiration")
            Config.cert_file = cert_path
            Config.key_file = key_path
            return True
        else:
            logger.debug("Certificate expires within 3 days, will download new one")
            return False
            
    except Exception as e:
        logger.error(f"Error checking certificate validity: {e}")
        return False


def initialize(base_config) -> bool:
    """Initialize the configuration by performing all required steps."""
    logger.debug("Initializing Hentai@Home client configuration...")

    Config.data_dir = base_config.get('data_dir', 'data')
    Config.cache_dir = base_config.get('cache_dir', 'cache')
    Config.log_dir = base_config.get('log_dir', 'log')
    Config.override_port = base_config.get('override_port', False)
    Config.hath_port = base_config.get('hath_port', 443)
    Config.zip_downloaded = base_config.get('zip_downloaded', True)
    Config.log_overrided = base_config.get('override_log', False)
    Config.override_level = base_config.get('log_level', 'DEBUG')
    Config.disable_ip_check = base_config.get('disable_ip_check', False)
    Config.download_proxy = base_config.get('download_proxy')
    Config.rpc_proxy = base_config.get('rpc_proxy')

    # Step 1: Read client credentials
    if not read_client_credentials(Config.data_dir):
        return False
    
    # Step 2: Get server time
    if not get_server_time():
        return False
    
    # Step 3: Get client configuration
    if not get_client_config():
        return False
    
    # Step 4: Get SSL certificate
    if not get_ssl_certificate():
        return False
    
    logger.debug("Configuration initialization completed successfully")
    return True


def load_from_config_file():
    cache_file = 'config/config.json'
    if not os.path.exists(cache_file):
        logger.error("Configuration cache file not found")
        return False

    with open(cache_file, 'r') as f:
        try:
            config_data = json.load(f)
            Config.data_dir = config_data.get('data_dir', 'data')
            Config.cache_dir = config_data.get('cache_dir', 'cache')
            Config.log_dir = config_data.get('log_dir', 'log')
            Config.override_port = config_data.get('override_port', False)
            Config.hath_port = config_data.get('hath_port', 443)
            Config.zip_downloaded = config_data.get('zip_downloaded', True)
            Config.log_overrided = config_data.get('override_log', False)
            Config.override_level = config_data.get('log_level', 'DEBUG')
            Config.client_id = config_data.get('client_id', '')
            Config.client_key = config_data.get('client_key', '')
            Config.config = config_data.get('config', {})
            Config.rpc_server_ips = config_data.get('rpc_server_ips', [])
            Config.static_range = config_data.get('static_range', [])
            Config.static_range_count = config_data.get('static_range_count', None)
            Config.server_time = config_data.get('server_time', 0)
            Config.time_difference = config_data.get('time_difference', 0)
            Config.cert_file = config_data.get('cert_file', '')
            Config.key_file = config_data.get('key_file', '')
            Config.disable_ip_check = config_data.get('disable_ip_check', False)
            Config.download_proxy = config_data.get('download_proxy')
            Config.rpc_proxy = config_data.get('rpc_proxy')
            logger.info("Configuration loaded from cache file successfully")
            return True
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from config file: {e}")
            return False

def remove_config():
    """Remove the configuration cache file."""
    cache_file = 'config/config.json'
    try:
        if os.path.exists(cache_file):
            os.remove(cache_file)
            logger.debug("Configuration cache file removed")
        else:
            logger.debug("Configuration cache file does not exist, nothing to remove")
    except Exception as e:
        logger.error(f"Error removing config cache file: {e}")
    return True

def _get_rpc_host():
    """Get the RPC host to use - either from IP list or fallback domain."""
    if Config.rpc_server_ips:
        return Config.rpc_server_ips[0]
    return Config.rpc_fallback_domain

def _handle_rpc_failure():
    """Handle RPC failure by moving the failed IP to the end of the list."""
    if Config.rpc_server_ips and len(Config.rpc_server_ips) > 1:
        failed_ip = Config.rpc_server_ips.pop(0)
        Config.rpc_server_ips.append(failed_ip)
        logger.debug(f"Moved failed RPC server {failed_ip} to end of list. Next server: {Config.rpc_server_ips[0]}")
