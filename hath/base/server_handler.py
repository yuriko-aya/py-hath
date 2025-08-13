"""
Server handler for communicating with Hentai@Home servers.
"""

import time
import requests
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlencode

from .out import Out
from .settings import Settings
from .tools import Tools


class ServerHandler:
    """Handles communication with the Hentai@Home server."""
    
    # Class variable to track global login validation state
    _global_login_validated = False
    
    # Action types for server communication
    ACT_CLIENT_START = "client_start"
    ACT_STILL_ALIVE = "still_alive"
    ACT_DOWNLOAD_CERT = "server_stat"
    ACT_SERVER_STAT = "server_stat"
    ACT_CLIENT_LOGIN = "client_login"
    ACT_CLIENT_SETTINGS = "client_settings"
    ACT_GET_CERTIFICATE = "get_cert"
    ACT_CLIENT_SUSPEND = "client_suspend"
    ACT_CLIENT_RESUME = "client_resume"
    ACT_CLIENT_STOP = "client_stop"
    ACT_STATIC_RANGE_FETCH = "srfetch"
    ACT_DOWNLOADER_FETCH = "dlfetch"
    ACT_DOWNLOADER_FAILREPORT = "dlfails"
    ACT_OVERLOAD = "overload"
    
    def __init__(self, client):
        """Initialize the server handler."""
        self.client = client
        self.login_validated = False
        self.last_overload_notification = 0
    
    def load_client_settings_from_server(self):
        """Load client settings from server during startup."""
        Out.info(f"Connecting to the Hentai@Home Server to register client with ID {Settings.get_client_id()}...")
        
        try:
            # Get initial server stat
            if not self.refresh_server_stat():
                self.client.die_with_error("Failed to get initial stat from server.")
                return
            
            # Perform client login
            Out.info("Reading Hentai@Home client settings from server...")
            response = self._get_server_response(self.ACT_CLIENT_LOGIN)
            
            if response and response.get('status') == 'OK':
                self.login_validated = True
                ServerHandler._global_login_validated = True
                Out.info("Applying settings...")
                self._parse_and_update_settings(response.get('response_text', ''))
                Out.info("Finished applying settings")
            elif response and response.get('status') == 'FAIL':
                fail_code = response.get('fail_code', 'Unknown')
                self.client.die_with_error(f"Authentication failed: {fail_code}")
                return
            else:
                self.client.die_with_error("Failed to get a login response from server.")
                return
        except Exception as e:
            self.client.die_with_error(str(e))
    
    def refresh_server_settings(self) -> bool:
        """Refresh client settings from server."""
        Out.info("Refreshing Hentai@Home client settings from server...")
        response = self._get_server_response(self.ACT_CLIENT_SETTINGS)
        
        if response and response.get('status') == 'OK':
            Out.info("Applying refreshed settings...")
            self._parse_and_update_settings(response.get('response_text', ''))
            Out.info("Finished applying refreshed settings")
            return True
        else:
            Out.warning(f"Failed to refresh settings: {response}")
            return False
    
    def refresh_server_stat(self) -> bool:
        """Refresh server statistics."""
        Out.debug("Attempting to refresh server statistics...")
        response = self._get_server_response(self.ACT_SERVER_STAT)
        
        if response and response.get('status') == 'OK':
            Out.debug("Server stat refresh successful")
            # Parse server time and other stats
            response_text = response.get('response_text', '')
            if response_text:
                Out.debug(f"Server stat response: {response_text[:100]}...")
                # Basic parsing - in real implementation, this would be more comprehensive
                for line in response_text.split('\n'):
                    if line.startswith('server_time='):
                        server_time = int(line.split('=')[1])
                        current_time = int(time.time())
                        Settings.set_server_time_delta(server_time - current_time)
                        Out.debug(f"Server time delta set to: {server_time - current_time}")
                        break
            return True
        else:
            Out.debug(f"Server stat refresh failed: {response}")
            return False
    
    def notify_start(self) -> bool:
        """Notify server that client has started."""
        response = self._get_server_response(self.ACT_CLIENT_START)
        return response is not None and response.get('status') == 'OK'
    
    def notify_shutdown(self) -> bool:
        """Notify server that client is shutting down."""
        response = self._get_server_response(self.ACT_CLIENT_STOP)
        return response is not None and response.get('status') == 'OK'
    
    def notify_suspend(self) -> bool:
        """Notify server that client is suspended."""
        response = self._get_server_response(self.ACT_CLIENT_SUSPEND)
        return response is not None and response.get('status') == 'OK'
    
    def notify_resume(self) -> bool:
        """Notify server that client has resumed."""
        response = self._get_server_response(self.ACT_CLIENT_RESUME)
        return response is not None and response.get('status') == 'OK'
    
    def still_alive_test(self, resume: bool):
        """
        Perform still alive test with server using CakeSphere.
        
        Args:
            resume: If True, this is a resume operation (called when client resumes)
        """
        # Java: CakeSphere cs = new CakeSphere(this, client);
        # Java: cs.stillAlive(resume);
        from .cake_sphere import get_cake_sphere_manager
        
        cake_sphere_manager = get_cake_sphere_manager()
        cake_sphere_manager.still_alive_test(self, self.client, resume)
    
    def get_static_range_fetch_url(self, fileindex: str, xres: str, fileid: str) -> Optional[List[str]]:
        """Get URLs for fetching a file from static ranges."""
        # Java: getServerConnectionURL(ACT_STATIC_RANGE_FETCH, fileindex + ";" + xres + ";" + fileid)
        add_param = f"{fileindex};{xres};{fileid}"
        
        response = self._get_server_response(self.ACT_STATIC_RANGE_FETCH, {'add': add_param})
        
        if response and response.get('status') == 'OK':
            response_text = response.get('response_text', '')
            urls = []
            for line in response_text.split('\n'):
                line = line.strip()
                if line and line.startswith('http'):
                    urls.append(line)
            return urls if urls else None
        else:
            Out.info(f"Failed to request static range download link for {fileid}.")
        return None
    
    def _get_server_response(self, action: str, extra_params: Optional[Dict[str, str]] = None) -> Optional[Dict[str, str]]:
        """Get response from server for the given action."""
        try:
            Out.debug(f"Making server request for action: {action}")
            
            # Build request parameters based on action type
            if action == self.ACT_SERVER_STAT:
                # server_stat uses simple format: clientbuild, act
                params = {
                    'clientbuild': str(Settings.CLIENT_BUILD),
                    'act': action
                }
            elif action == self.ACT_CLIENT_LOGIN:
                # client_login uses: clientbuild, act, cid, acttime, actkey
                current_time = Settings.get_server_time()
                client_id = str(Settings.get_client_id())
                client_key = Settings.get_client_key()
                add = ""  # Empty add parameter for client_login
                
                # Calculate actkey using Java formula: SHA1("hentai@home-" + act + "-" + add + "-" + cid + "-" + acttime + "-" + clientkey)
                actkey_string = f"hentai@home-{action}-{add}-{client_id}-{current_time}-{client_key}"
                actkey = Tools.get_sha1_string(actkey_string)
                
                params = {
                    'clientbuild': str(Settings.CLIENT_BUILD),
                    'act': action,
                    'cid': client_id,
                    'acttime': str(current_time),
                    'actkey': actkey
                }
            else:
                # All other actions use getURLQueryString format: clientbuild, act, add, cid, acttime, actkey
                current_time = Settings.get_server_time()
                client_id = str(Settings.get_client_id())
                client_key = Settings.get_client_key()
                add = ""  # Default empty add parameter
                
                # Extract add parameter from extra_params if provided
                if extra_params and 'add' in extra_params:
                    add = extra_params['add']
                
                # Calculate actkey using Java formula: SHA1("hentai@home-" + act + "-" + add + "-" + cid + "-" + acttime + "-" + clientkey)
                actkey_string = f"hentai@home-{action}-{add}-{client_id}-{current_time}-{client_key}"
                actkey = Tools.get_sha1_string(actkey_string)
                
                params = {
                    'clientbuild': str(Settings.CLIENT_BUILD),
                    'act': action,
                    'add': add,
                    'cid': client_id,
                    'acttime': str(current_time),
                    'actkey': actkey
                }
            
            # Build URL
            url = f"{Settings.CLIENT_RPC_PROTOCOL}{Settings.CLIENT_RPC_HOST}/{Settings._rpc_path}"
            Out.debug(f"Request URL: {url}")
            Out.debug(f"Request params: {dict((k, v if k not in ['clientkey', 'actkey'] else '***') for k, v in params.items())}")
            
            # Make request - ALL RPC requests use GET method with URL parameters
            Out.debug("Sending HTTP request...")
            Out.debug(f"Using GET method for {action}")
            response = requests.get(url, params=params, timeout=30)
            
            Out.debug(f"HTTP response status: {response.status_code}")
            
            if response.status_code == 200:
                response_text = response.text.strip()
                Out.debug(f"Response text: {response_text[:200]}{'...' if len(response_text) > 200 else ''}")
                
                # Parse response
                if response_text.startswith('OK'):
                    Out.debug("Server response: OK")
                    return {
                        'status': 'OK',
                        'response_text': response_text[3:] if len(response_text) > 2 else ''
                    }
                elif response_text.startswith('FAIL'):
                    fail_code = response_text[5:] if len(response_text) > 4 else 'Unknown'
                    Out.debug(f"Server response: FAIL with code {fail_code}")
                    return {
                        'status': 'FAIL',
                        'fail_code': fail_code
                    }
                elif response_text.startswith('KEY_FAIL'):
                    # Handle KEY_FAIL response for client_login
                    fail_message = response_text[9:] if len(response_text) > 8 else 'Authentication failed'
                    Out.debug(f"Server response: KEY_FAIL - {fail_message}")
                    return {
                        'status': 'FAIL',
                        'fail_code': f'KEY_FAIL{fail_message}'
                    }
                else:
                    Out.debug(f"Unexpected response format: {response_text}")
                    # For unexpected formats, treat as failure
                    return {
                        'status': 'FAIL', 
                        'fail_code': response_text
                    }
            else:
                Out.debug(f"HTTP error response: {response.status_code} - {response.text}")
            
            return None
            
        except Exception as e:
            Out.error(f"Server communication error: {e}")
            Out.debug(f"Exception details: {type(e).__name__}: {str(e)}")
            return None
    
    def _parse_and_update_settings(self, settings_text: str):
        """Parse and update settings from server response."""
        if not settings_text:
            return
        
        Out.debug("=== Parsing server settings ===")
        Out.debug(f"Raw settings response:\n{settings_text}")
        
        # Track settings for logging
        parsed_settings = {}
        
        for line in settings_text.split('\n'):
            line = line.strip()
            if not line or '=' not in line:
                continue
                
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip()
            
            # Store for logging
            parsed_settings[key] = value
            
            # Parse specific settings (matching Java parseAndUpdateSettings)
            try:
                if key == 'client_port' or key == 'port':
                    port = int(value)
                    Settings.set_client_port(port)
                    Out.info(f"Client port set to: {port}")
                    
                elif key == 'host':
                    Settings._client_host = value
                    Out.info(f"Client host set to: {value}")
                    
                elif key == 'throttle_bytes':
                    throttle = int(value)
                    Settings.set_throttle_bytes_per_sec(throttle)
                    Out.info(f"Throttle set to: {throttle} bytes/sec")
                    
                elif key == 'disklimit_bytes':
                    # Already in bytes
                    disk_limit = int(value)
                    Settings.set_disk_limit_bytes(disk_limit)
                    Out.info(f"Disk limit set to: {disk_limit} bytes")
                    
                elif key == 'diskremaining_bytes':
                    # Already in bytes  
                    disk_remaining = int(value)
                    Settings._disk_remaining_bytes = disk_remaining
                    Out.debug(f"Disk remaining: {disk_remaining} bytes")
                    
                elif key == 'static_ranges':
                    self._parse_static_ranges(value)
                    Out.info(f"Static ranges updated: {Settings.get_static_range_count()} ranges")
                    
                elif key == 'rpc_server_port':
                    rpc_port = int(value)
                    Settings._rpc_server_port = rpc_port
                    Out.debug(f"RPC server port: {rpc_port}")
                    
                elif key == 'max_connections':
                    max_conn = int(value)
                    Settings._override_conns = max_conn
                    Out.info(f"Max connections set to: {max_conn}")
                    
                elif key == 'request_server':
                    # Handle RPC server hostnames
                    if value:
                        Settings._rpc_servers = value.split(';')
                        Out.info(f"RPC servers: {Settings._rpc_servers}")
                        
                elif key == 'warn_new_client':
                    Settings._warn_new_client = value.lower() in ['true', '1', 'yes']
                    Out.debug(f"Warn new client: {Settings._warn_new_client}")
                    
                elif key == 'use_less_memory':
                    Settings._use_less_memory = value.lower() in ['true', '1', 'yes']
                    Out.debug(f"Use less memory: {Settings._use_less_memory}")
                    
                elif key == 'disable_bwm':
                    Settings._disable_bwm = value.lower() in ['true', '1', 'yes']
                    Out.debug(f"Disable BWM: {Settings._disable_bwm}")
                    
                elif key == 'disable_downloads':
                    Settings._disable_download_bwm = value.lower() in ['true', '1', 'yes']
                    Out.debug(f"Disable download BWM: {Settings._disable_download_bwm}")
                    
                elif key == 'disable_logging':
                    Settings._disable_logs = value.lower() in ['true', '1', 'yes']
                    Out.debug(f"Disable logging: {Settings._disable_logs}")
                    
                elif key == 'enable_log_flushing':
                    Settings._flush_logs = value.lower() in ['true', '1', 'yes']
                    Out.debug(f"Enable log flushing: {Settings._flush_logs}")
                    
                elif key == 'verify_cache':
                    Settings._verify_cache = value.lower() in ['true', '1', 'yes']
                    Out.debug(f"Verify cache: {Settings._verify_cache}")
                    
                elif key == 'disable_ip_origin_check':
                    Settings._disable_ip_origin_check = value.lower() in ['true', '1', 'yes']
                    Out.debug(f"Disable IP origin check: {Settings._disable_ip_origin_check}")
                    
                elif key == 'image_proxy_host':
                    Settings._image_proxy_host = value if value else None
                    Out.debug(f"Image proxy host: {value}")
                    
                elif key == 'image_proxy_port':
                    if value:
                        Settings._image_proxy_port = int(value)
                        Out.debug(f"Image proxy port: {value}")
                        
                elif key == 'image_proxy_type':
                    Settings._image_proxy_type = value if value else None
                    Out.debug(f"Image proxy type: {value}")
                    
                else:
                    # Log unknown settings for debugging
                    Out.debug(f"Unknown setting: {key} = {value}")
                    
            except (ValueError, TypeError) as e:
                Out.warning(f"Failed to parse setting {key}={value}: {e}")
        
        # Log summary of all parsed settings
        Out.debug("=== Settings parsing summary ===")
        for key, value in parsed_settings.items():
            Out.debug(f"  {key} = {value}")
        Out.debug(f"Total settings parsed: {len(parsed_settings)}")
    
    def _parse_static_ranges(self, ranges_text: str):
        """Parse static ranges from server response."""
        if not ranges_text:
            Settings._static_ranges = {}
            Settings._current_static_range_count = 0
            return
        
        Out.debug(f"Parsing static ranges: {ranges_text}")
        
        # Static ranges use semicolon separator, not comma
        # Format is typically: "01;02;03;04" or similar
        ranges = ranges_text.split(';')
        range_dict = {}
        
        for range_id in ranges:
            range_id = range_id.strip()
            if range_id:
                range_dict[range_id] = 1  # Value is 1 for active ranges
        
        Settings._static_ranges = range_dict
        Settings._current_static_range_count = len(range_dict)
        
        Out.debug(f"Parsed {len(range_dict)} static ranges: {list(range_dict.keys())}")
    
    def download_certificate(self) -> bool:
        """Download SSL certificate from server."""
        Out.info("Downloading SSL certificate from server...")
        
        try:
            # Make direct HTTP request to get binary certificate data
            current_time = Settings.get_server_time()
            client_id = str(Settings.get_client_id())
            client_key = Settings.get_client_key()
            add = ""  # Empty add parameter for get_cert
            
            # Calculate actkey using Java formula
            actkey_string = f"hentai@home-{self.ACT_GET_CERTIFICATE}-{add}-{client_id}-{current_time}-{client_key}"
            actkey = Tools.get_sha1_string(actkey_string)
            
            params = {
                'clientbuild': str(Settings.CLIENT_BUILD),
                'act': self.ACT_GET_CERTIFICATE,
                'add': add,
                'cid': client_id,
                'acttime': str(current_time),
                'actkey': actkey
            }
            
            # Build URL
            url = f"{Settings.CLIENT_RPC_PROTOCOL}{Settings.CLIENT_RPC_HOST}/{Settings._rpc_path}"
            Out.debug(f"Certificate request URL: {url}")
            Out.debug(f"Certificate request params: {dict((k, v if k not in ['actkey'] else '***') for k, v in params.items())}")
            
            # Make GET request for certificate
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                cert_data = response.content  # Get binary content
                
                if cert_data and len(cert_data) > 100:  # Basic sanity check for certificate data
                    # Save PKCS#12 certificate to data directory
                    p12_path = Settings.get_data_dir() / "client.p12"
                    
                    # Save the PKCS#12 data
                    with open(p12_path, 'wb') as f:
                        f.write(cert_data)
                    
                    # Set appropriate permissions (readable only by owner)
                    p12_path.chmod(0o600)
                    
                    Out.info("SSL certificate (PKCS#12) downloaded successfully")
                    return True
                else:
                    Out.error("Invalid certificate data received from server")
                    return False
            else:
                Out.error(f"Failed to download certificate: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            Out.error(f"Error downloading certificate: {e}")
            return False
    
    def get_certificate_paths(self) -> tuple:
        """Get paths to certificate and key files."""
        p12_path = Settings.get_data_dir() / "client.p12"
        return str(p12_path), None  # Return PKCS#12 path and None for key path
    
    def is_certificate_valid(self) -> bool:
        """Check if SSL certificate exists and is valid."""
        try:
            from cryptography.hazmat.primitives.serialization import pkcs12
            import datetime
            
            p12_path = Settings.get_data_dir() / "client.p12"
            
            # Check PKCS#12 certificate
            if p12_path.exists():
                try:
                    with open(p12_path, 'rb') as f:
                        p12_data = f.read()
                        
                        # Try different passwords for PKCS#12 (H@H uses client key as password)
                        passwords_to_try = [
                            Settings.get_client_key().encode(),  # Most likely - client key
                            None, 
                            b'', 
                            str(Settings.get_client_id()).encode(),
                            b'hentai@home'
                        ]
                        
                        private_key = None
                        certificate = None
                        
                        for password in passwords_to_try:
                            try:
                                private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                                    p12_data, password=password
                                )
                                Out.debug(f"Successfully validated PKCS#12 with password: {'None' if password is None else 'provided'}")
                                break
                            except Exception as e:
                                Out.debug(f"Failed to validate PKCS#12 with password attempt: {e}")
                                continue
                        
                        if certificate:
                            # Check if certificate is expired or expires soon (within 24 hours)
                            # Use timezone-aware datetime to match certificate timestamps
                            now = datetime.datetime.now(datetime.timezone.utc)
                            expires_soon = now + datetime.timedelta(hours=24)
                            
                            # Use UTC-aware certificate timestamp
                            if certificate.not_valid_after_utc <= expires_soon:
                                Out.info(f"SSL certificate is expired or expires soon (expires: {certificate.not_valid_after_utc})")
                                return False
                            
                            Out.debug(f"SSL certificate is valid until: {certificate.not_valid_after_utc}")
                            return True
                except Exception as e:
                    Out.debug(f"Failed to validate PKCS#12 certificate: {e}")
            
            return False
                
        except Exception as e:
            Out.warning(f"Error checking certificate validity: {e}")
            return False
    
    @staticmethod
    def is_login_validated() -> bool:
        """Check if login has been validated."""
        return ServerHandler._global_login_validated
    
    def get_downloader_fetch_url(self, gid: int, page: int, fileindex: int, xres: str, retry: int) -> Optional[str]:
        """Get download URL for a gallery file.
        
        Args:
            gid: Gallery ID
            page: Page number
            fileindex: File index
            xres: Resolution
            retry: Retry count
            
        Returns:
            Download URL or None if failed
        """
        try:
            params = {
                'gid': gid,
                'page': page,
                'fileindex': fileindex,
                'xres': xres,
                'retry': retry
            }
            
            response = self._get_server_response(self.ACT_DOWNLOADER_FETCH, params)
            
            if response and response.get('status') == 'OK':
                return response.get('response_text', '').strip()
            else:
                Out.warning(f"Failed to get download URL for gid={gid} page={page}")
                return None
                
        except Exception as e:
            Out.warning(f"Error getting download URL: {e}")
            return None
    
    def report_downloader_failures(self, failures: List[str]):
        """Report download failures to server.
        
        Args:
            failures: List of failure identifiers
        """
        if not failures:
            return
        
        try:
            # Format failures for reporting
            failure_data = '\n'.join(failures)
            
            response = self._get_server_response(self.ACT_DOWNLOADER_FAILREPORT, {'failures': failure_data})
            
            if response and response.get('status') == 'OK':
                Out.debug(f"Reported {len(failures)} download failures to server")
            else:
                Out.warning("Failed to report download failures")
                
        except Exception as e:
            Out.warning(f"Error reporting download failures: {e}")
    
    def get_url_query_string(self, action: str, additional_param: str = "") -> str:
        """Get URL query string for server requests.
        
        Args:
            action: Action to perform
            additional_param: Additional parameter
            
        Returns:
            URL query string
        """
        try:
            # Base parameters required for all requests
            params = {
                'clientbuild': Settings.CLIENT_BUILD,
                'clienttime': int(time.time() + Settings.get_server_time_delta()),
                'clientid': Settings.get_client_id(),
                'clientkey': Settings.get_client_key(),
                'act': action
            }
            
            # Add additional parameter if provided
            if additional_param:
                params['add'] = additional_param
            
            return urlencode(params)
            
        except Exception as e:
            Out.warning(f"Error building query string: {e}")
            return ""
    
    def notify_start(self) -> bool:
        """Notify server that client startup is complete.
        
        Returns:
            True if successful
        """
        try:
            response = self._get_server_response(self.ACT_CLIENT_START)
            
            if response and response.get('status') == 'OK':
                Out.info("Server notified of successful startup")
                return True
            else:
                Out.warning("Failed to notify server of startup")
                return False
                
        except Exception as e:
            Out.warning(f"Error notifying server of startup: {e}")
            return False
    
    def download_client_certificate(self) -> bool:
        """Download client certificate from server.
        
        Returns:
            True if successful
        """
        try:
            Out.info("Downloading client certificate from server...")
            
            # Request certificate from server
            response = self._get_server_response(self.ACT_GET_CERTIFICATE)
            
            if response and response.get('status') == 'OK':
                cert_data = response.get('response_text', '')
                
                if cert_data:
                    # Save certificate to file
                    cert_path = Settings.get_data_dir() / 'client.p12'
                    
                    try:
                        # Certificate data should be base64 encoded
                        import base64
                        cert_bytes = base64.b64decode(cert_data)
                        
                        # Write certificate file
                        cert_path.write_bytes(cert_bytes)
                        
                        # Validate the certificate
                        if self.is_certificate_valid():
                            Out.info(f"Client certificate downloaded and saved to {cert_path}")
                            return True
                        else:
                            Out.warning("Downloaded certificate failed validation")
                            return False
                            
                    except Exception as e:
                        Out.warning(f"Failed to save certificate: {e}")
                        return False
                else:
                    Out.warning("Empty certificate data received from server")
                    return False
            else:
                Out.warning("Failed to download certificate from server")
                return False
                
        except Exception as e:
            Out.warning(f"Error downloading client certificate: {e}")
            return False
