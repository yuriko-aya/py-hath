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
    """Handles communication with Hentai@Home servers."""
    
    # Action constants
    ACT_SERVER_STAT = "server_stat"
    ACT_GET_BLACKLIST = "get_blacklist"
    ACT_GET_CERTIFICATE = "get_cert"
    ACT_CLIENT_LOGIN = "client_login"
    ACT_CLIENT_SETTINGS = "client_settings"
    ACT_CLIENT_START = "client_start"
    ACT_CLIENT_SUSPEND = "client_suspend"
    ACT_CLIENT_RESUME = "client_resume"
    ACT_CLIENT_STOP = "client_stop"
    ACT_STILL_ALIVE = "still_alive"
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
            self._parse_and_update_settings(response.get('response_text', ''))
            Out.info("Finished applying settings")
            return True
        else:
            Out.warning("Failed to refresh settings")
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
    
    def still_alive_test(self, retry: bool) -> bool:
        """Perform still alive test with server."""
        response = self._get_server_response(self.ACT_STILL_ALIVE)
        return response is not None and response.get('status') == 'OK'
    
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
        
        for line in settings_text.split('\n'):
            line = line.strip()
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                # Parse specific settings
                if key == 'client_port' or key == 'port':
                    Out.debug(f"Setting client port to: {value}")
                    Settings.set_client_port(int(value))
                elif key == 'disk_limit':
                    Settings.set_disk_limit_bytes(int(value) * 1024 * 1024)  # MB to bytes
                elif key == 'static_ranges':
                    self._parse_static_ranges(value)
                # Add more setting parsing as needed
    
    def _parse_static_ranges(self, ranges_text: str):
        """Parse static ranges from server response."""
        if not ranges_text:
            return
        
        # Static ranges are typically in format like "01,02,03,04"
        ranges = ranges_text.split(',')
        Settings._static_ranges = {range_id.strip(): 1 for range_id in ranges if range_id.strip()}
        Settings._current_static_range_count = len(Settings._static_ranges)
    
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
                            now = datetime.datetime.now(datetime.timezone.utc)
                            expires_soon = now + datetime.timedelta(hours=24)
                            
                            if certificate.not_valid_after <= expires_soon:
                                Out.info("SSL certificate is expired or expires soon")
                                return False
                            
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
        # This would be implemented with a global state
        return True  # Placeholder
