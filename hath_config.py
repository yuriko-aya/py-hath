import os
import requests
import time
import hashlib
import ipaddress
import sys
import rpc_manager

from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from typing import Dict, Optional, Tuple, Any, List
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class HathConfig:
    """Configuration handler for Hentai@Home client."""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self.client_id: Optional[str] = None
        self.client_key: Optional[str] = None
        self.server_time: Optional[int] = None
        self.time_difference: Optional[int] = None
        self.config: Dict[str, str] = {}
        self.cert_file: Optional[str] = None
        self.key_file: Optional[str] = None
        self.is_server_ready: Optional[bool] = False
        self.client_build: str = "176"  # Fixed client build version
        
        # RPC server IP list for failover (converted to standard IPv4 format)
        self.rpc_server_ips: list = []
        self.rpc_fallback_domain: str = "rpc.hentaiathome.net"

        # Static range
        self.static_range_count: Optional[int] = None
        self.static_range: list = []
        
    def _convert_ipv6_mapped_to_ipv4(self, ip_list: List[str]) -> List[str]:
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
        
    def _get_rpc_host(self) -> str:
        """Get the RPC host to use - either from IP list or fallback domain."""
        if self.rpc_server_ips:
            return self.rpc_server_ips[0]
        return self.rpc_fallback_domain

    def _handle_rpc_failure(self) -> None:
        """Handle RPC failure by moving the failed IP to the end of the list."""
        if self.rpc_server_ips and len(self.rpc_server_ips) > 1:
            failed_ip = self.rpc_server_ips.pop(0)
            self.rpc_server_ips.append(failed_ip)
            logger.debug(f"Moved failed RPC server {failed_ip} to end of list. Next server: {self.rpc_server_ips[0]}")
            
    def read_client_credentials(self) -> bool:
        """Read client_id and client_key from data/client_login file."""
        client_login_path = os.path.join(self.data_dir, "client_login")
        
        try:
            with open(client_login_path, 'r') as f:
                content = f.read().strip()
                
            if '-' in content:
                self.client_id, self.client_key = content.split('-', 1)
                logger.info(f"Loaded client credentials: ID={self.client_id}")
                return True
            else:
                logger.error("Invalid format in client_login file. Expected 'id-key' format.")
                return False
                
        except FileNotFoundError:
            logger.warning(f"client_login file not found in {self.data_dir} directory")
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
                self.client_id = client_id
                self.client_key = client_key
                
                logger.info(f"Loaded client credentials: ID={self.client_id}")
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

    def get_server_time(self) -> bool:
        """Get server time from remote server."""
        try:
            local_time_before = int(time.time())
            url_path = f'/15/rpc?clientbuild={self.client_build}&act=server_stat'
            response = rpc_manager._make_rpc_request(url_path, timeout=10, configuration=self)
            
            # Parse key=value format
            for line in response.text.strip().split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    if key.strip() == 'server_time':
                        self.server_time = int(value.strip())
                        # Calculate time difference: server_time - local_time
                        self.time_difference = self.server_time - local_time_before
                        logger.debug(f"Server time: {self.server_time}")
                        logger.debug(f"Time difference: {self.time_difference} seconds")
                        return True
                        
            logger.error("server_time not found in response")
            return False
            
        except Exception as e:
            logger.error(f"Error getting server time: {e}")
            return False

    def get_current_acttime(self) -> int:
        """Get current acttime (local time + time difference)."""
        current_local_time = int(time.time())
        return current_local_time + (self.time_difference or 0)

    def generate_actkey(self, act: str, add: str = "") -> str:
        """Generate actkey for authentication."""
        # actkey is SHA-1 hash of "hentai@home-{act}-{add}-{client_id}-{current_time}-{client_key}"
        current_acttime = self.get_current_acttime()
        data = f"hentai@home-{act}-{add}-{self.client_id}-{current_acttime}-{self.client_key}"
        return hashlib.sha1(data.encode()).hexdigest()

    def get_client_config(self, force_refresh=False) -> bool:
        """Get client configuration from remote server."""
        try:
            current_acttime = self.get_current_acttime()
            if force_refresh:
                actkey = self.generate_actkey("client_settings")
                url_path = (f"/15/rpc?clientbuild={self.client_build}&act=client_settings"
                        f"&cid={self.client_id}&acttime={current_acttime}&actkey={actkey}")
            else:
                actkey = self.generate_actkey("client_login")
                url_path = (f"/15/rpc?clientbuild={self.client_build}&act=client_login"
                        f"&cid={self.client_id}&acttime={current_acttime}&actkey={actkey}")

            response = rpc_manager._make_rpc_request(url_path, timeout=10, configuration=self)
            
            response_text = response.text.strip()
            
            # Must have "OK" in response for success
            if "OK" not in response_text:
                logger.error(f"Server did not return OK status: {response_text}")
                return False

            # If disable_logging is set, but not in return, remove it from config
            if self.config.get('disable_logging') and not 'disable_logging' in response_text:
                self.config.pop('disable_logging', None)

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
                            self.rpc_server_ips = self._convert_ipv6_mapped_to_ipv4(raw_ips)
                        else:
                            logger.warning("Empty rpc_server_ip received")

                    if key == 'static_ranges':
                        self.static_range = [sr for sr in value.split(';') if sr]
                        self.static_range_count = len(self.static_range)
                        logger.debug(f"Parsed {self.static_range_count} static ranges: {self.static_range}")
                    
                    if key == 'static_range_count':
                        self.static_range_count = int(value)
                        logger.debug(f"Update static range count: {self.static_range_count}")

                    self.config[key] = value

            logger.info("Client configuration loaded successfully")
            logger.debug(f"Host: {self.config.get('host')}")
            logger.debug(f"Port: {self.config.get('port')}")
            if self.rpc_server_ips:
                logger.debug(f"RPC servers: {self.rpc_server_ips}")

            # Save configuration to cache file for worker processes
            self.save_config_cache()

            return True
            
        except Exception as e:
            logger.error(f"Error getting client config: {e}")
            return False

    def save_config_cache(self) -> bool:
        """Save current configuration to cache file for worker processes."""
        try:
            import json
            cache_file = os.path.join(self.data_dir, '.hath_config_cache.json')
            
            cache_data = {
                'client_id': self.client_id,
                'client_key': self.client_key,
                'config': dict(self.config),
                'rpc_server_ips': list(self.rpc_server_ips),
                'static_range': list(self.static_range),
                'static_range_count': self.static_range_count,
                'server_time': self.server_time,
                'time_difference': self.time_difference,
                'cert_file': self.cert_file,
                'key_file': self.key_file,
                'timestamp': time.time(),
                'process_pid': os.getpid()  # Track which process created this cache
            }
            
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            
            logger.debug(f"Configuration cached to {cache_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving config cache: {e}")
            return False

    def load_config_cache(self) -> bool:
        """Load configuration from cache file (for worker processes)."""
        try:
            import json
            cache_file = os.path.join(self.data_dir, '.hath_config_cache.json')
            
            if not os.path.exists(cache_file):
                logger.warning("Cannot find the config file. May be just started?")
                return False

            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
                        
            # Restore configuration
            self.client_id = cache_data.get('client_id')
            self.client_key = cache_data.get('client_key')
            self.config = dict(cache_data.get('config', {}))
            self.rpc_server_ips = list(cache_data.get('rpc_server_ips', []))
            self.static_range = list(cache_data.get('static_range', []))
            self.static_range_count = cache_data.get('static_range_count', 0)
            self.server_time = cache_data.get('server_time')
            self.time_difference = cache_data.get('time_difference')
            self.cert_file = cache_data.get('cert_file')
            self.key_file = cache_data.get('key_file')
            
            logger.debug(f"Configuration loaded from cache: {len(self.config)} config items, {len(self.rpc_server_ips)} RPC servers")
            return True
            
        except Exception as e:
            logger.error(f"Error loading config cache: {e}")
            # If there's an error loading, try to clean up the corrupted cache
            try:
                cache_file = os.path.join(self.data_dir, '.hath_config_cache.json')
                if os.path.exists(cache_file):
                    os.remove(cache_file)
                    logger.debug("Removed corrupted config cache file")
            except OSError:
                pass
            return False

    def cleanup_config_cache(self) -> None:
        """Clean up the configuration cache file."""
        try:
            cache_file = os.path.join(self.data_dir, '.hath_config_cache.json')
            if os.path.exists(cache_file):
                os.remove(cache_file)
                logger.debug("Configuration cache file cleaned up")
        except Exception as e:
            logger.error(f"Error cleaning up config cache: {e}")

    def _check_certificate_validity(self) -> bool:
        """Check if existing certificate is valid and has more than 3 days until expiration,
        and is not more than one week old."""
        try:
            cert_path = os.path.join(self.data_dir, "client.crt")
            key_path = os.path.join(self.data_dir, "client.key")
            
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
            expiration_date = certificate.not_valid_after
            current_date = datetime.utcnow()
            days_until_expiration = (expiration_date - current_date).days
            
            logger.debug(f"Certificate expires on: {expiration_date}")
            logger.debug(f"Days until expiration: {days_until_expiration}")
            
            if days_until_expiration > 3:
                logger.debug("Certificate is valid, not too old, and has more than 3 days until expiration")
                self.cert_file = cert_path
                self.key_file = key_path
                return True
            else:
                logger.debug("Certificate expires within 3 days, will download new one")
                return False
                
        except Exception as e:
            logger.error(f"Error checking certificate validity: {e}")
            return False

    def get_ssl_certificate(self, force_refresh: bool = False) -> bool:
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
        if not force_refresh and self._check_certificate_validity():
            logger.debug("Using existing valid certificate")
            return True
        
        if force_refresh:
            logger.debug("Force refresh requested, downloading new certificate...")
        
        try:
            current_acttime = self.get_current_acttime()
            actkey = self.generate_actkey("get_cert")
            url_path = (f"/15/rpc?clientbuild={self.client_build}&act=get_cert"
                       f"&add=&cid={self.client_id}&acttime={current_acttime}&actkey={actkey}")
            
            logger.debug("Downloading new SSL certificate...")
            response = rpc_manager._make_rpc_request(url_path, timeout=30, configuration=self)
            
            # Save PKCS#12 certificate
            p12_path = os.path.join(self.data_dir, "client.p12")
            with open(p12_path, 'wb') as f:
                f.write(response.content)
            
            # Convert PKCS#12 to separate cert and key files
            self._convert_p12_to_pem(p12_path)
            
            logger.debug("SSL certificate downloaded and converted successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error getting SSL certificate: {e}")
            return False

    def _convert_p12_to_pem(self, p12_path: str) -> None:
        """Convert PKCS#12 certificate to separate PEM files with full certificate chain."""
        try:
            with open(p12_path, 'rb') as f:
                p12_data = f.read()
            
            if not self.client_key:
                raise ValueError("Client key is required for PKCS#12 conversion")
            
            # Load PKCS#12 with client_key as password
            private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                p12_data, self.client_key.encode()
            )
            
            if not certificate:
                raise ValueError("No certificate found in PKCS#12 file")
            
            if not private_key:
                raise ValueError("No private key found in PKCS#12 file")
            
            # Save certificate with full chain
            cert_path = os.path.join(self.data_dir, "client.crt")
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
            
            self.cert_file = cert_path
            
            # Save private key
            key_path = os.path.join(self.data_dir, "client.key")
            with open(key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            self.key_file = key_path
            
            logger.debug(f"Certificate saved to: {cert_path}")
            logger.debug(f"Private key saved to: {key_path}")
            
        except Exception as e:
            logger.error(f"Error converting PKCS#12 certificate: {e}")
            raise

    def initialize(self) -> bool:
        """Initialize the configuration by performing all required steps."""
        logger.debug("Initializing Hentai@Home client configuration...")
        
        # Ensure data directory exists
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Step 1: Read client credentials
        if not self.read_client_credentials():
            return False
        
        # Step 2: Get server time
        if not self.get_server_time():
            return False
        
        # Step 3: Get client configuration
        if not self.get_client_config():
            return False
        
        # Step 4: Get SSL certificate
        if not self.get_ssl_certificate():
            return False
        
        logger.debug("Configuration initialization completed successfully")
        return True

    def notify_client_start(self) -> bool:
        """Notify the server that the client has started."""
        try:
            current_acttime = self.get_current_acttime()
            actkey = self.generate_actkey("client_start")
            url_path = (f"/15/rpc?clientbuild={self.client_build}&act=client_start"
                       f"&add=&cid={self.client_id}&acttime={current_acttime}&actkey={actkey}")
            
            logger.debug("Notifying server that client has started...")
            response = rpc_manager._make_rpc_request(url_path, timeout=60, configuration=self)
            
            logger.debug("Server notification sent successfully")
            logger.debug(f"Server response: {response.text.strip()}")
            return True
            
        except Exception as e:
            logger.error(f"Error notifying server of client start: {e}")
            return False

    def get_flask_config(self) -> Dict[str, Any]:
        """Get Flask configuration from the loaded config."""
        # Always use 0.0.0.0 as host
        server_port = self.config.get('port')
        
        # Critical failure if no port from server
        if not server_port:
            raise RuntimeError("CRITICAL: No port received from server configuration. Client cannot start without valid server configuration.")
        
        return {
            'host': '0.0.0.0',  # Always bind to all interfaces
            'port': int(server_port),  # Use port from server
            'ssl_context': (self.cert_file, self.key_file) if self.cert_file and self.key_file else None,  # Only for Flask app.run()
            'debug': False,
            'threaded': True
        }
