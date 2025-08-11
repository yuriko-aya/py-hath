"""
Client API for programmatic control of the Hentai@Home client.

This class provides hooks for controlling the client, allowing external
tools and scripts to suspend, resume, and modify settings programmatically.
"""

from typing import TYPE_CHECKING
from .client_api_result import ClientAPIResult
from .out import Out

if TYPE_CHECKING:
    from .hentai_at_home_client import HentaiAtHomeClient


class ClientAPI:
    """API for programmatic control of the Hentai@Home client."""
    
    # API Command constants (matching Java implementation)
    API_COMMAND_CLIENT_START = 1
    API_COMMAND_CLIENT_SUSPEND = 2
    API_COMMAND_MODIFY_SETTING = 3
    API_COMMAND_REFRESH_SETTINGS = 4
    API_COMMAND_CLIENT_RESUME = 5
    
    def __init__(self, client: 'HentaiAtHomeClient'):
        """Initialize the Client API.
        
        Args:
            client: The HentaiAtHomeClient instance to control
        """
        self.client = client
    
    def client_suspend(self, suspend_time: int) -> ClientAPIResult:
        """Suspend the client for the specified number of seconds.
        
        Args:
            suspend_time: Number of seconds to suspend (max 86400 = 24 hours)
            
        Returns:
            ClientAPIResult with "OK" or "FAIL"
        """
        try:
            Out.debug(f"ClientAPI: Suspending client for {suspend_time} seconds")
            success = self.client.suspend_master_thread(suspend_time)
            result_text = "OK" if success else "FAIL"
            return ClientAPIResult(self.API_COMMAND_CLIENT_SUSPEND, result_text)
        except Exception as e:
            Out.error(f"ClientAPI: Failed to suspend client: {e}")
            return ClientAPIResult(self.API_COMMAND_CLIENT_SUSPEND, "FAIL")
    
    def client_resume(self) -> ClientAPIResult:
        """Resume the client if it's currently suspended.
        
        Returns:
            ClientAPIResult with "OK" or "FAIL"
        """
        try:
            Out.debug("ClientAPI: Resuming client")
            success = self.client.resume_master_thread()
            result_text = "OK" if success else "FAIL"
            return ClientAPIResult(self.API_COMMAND_CLIENT_RESUME, result_text)
        except Exception as e:
            Out.error(f"ClientAPI: Failed to resume client: {e}")
            return ClientAPIResult(self.API_COMMAND_CLIENT_RESUME, "FAIL")
    
    def refresh_settings(self) -> ClientAPIResult:
        """Refresh client settings from the server.
        
        Returns:
            ClientAPIResult with "OK" or "FAIL"
        """
        try:
            Out.debug("ClientAPI: Refreshing settings from server")
            server_handler = self.client.get_server_handler()
            if server_handler:
                success = server_handler.refresh_server_settings()
                result_text = "OK" if success else "FAIL"
            else:
                Out.warning("ClientAPI: Server handler not available")
                result_text = "FAIL"
            return ClientAPIResult(self.API_COMMAND_REFRESH_SETTINGS, result_text)
        except Exception as e:
            Out.error(f"ClientAPI: Failed to refresh settings: {e}")
            return ClientAPIResult(self.API_COMMAND_REFRESH_SETTINGS, "FAIL")
    
    def modify_setting(self, setting_name: str, setting_value: str) -> ClientAPIResult:
        """Modify a client setting (placeholder implementation).
        
        Args:
            setting_name: Name of the setting to modify
            setting_value: New value for the setting
            
        Returns:
            ClientAPIResult with "OK" or "FAIL"
        """
        try:
            Out.debug(f"ClientAPI: Modifying setting {setting_name} = {setting_value}")
            # TODO: Implement setting modification when Settings class supports it
            # For now, just return OK as a placeholder
            Out.warning("ClientAPI: Setting modification not yet implemented")
            return ClientAPIResult(self.API_COMMAND_MODIFY_SETTING, "FAIL")
        except Exception as e:
            Out.error(f"ClientAPI: Failed to modify setting: {e}")
            return ClientAPIResult(self.API_COMMAND_MODIFY_SETTING, "FAIL")
    
    def get_client_status(self) -> dict:
        """Get current client status information.
        
        Returns:
            Dictionary with client status information
        """
        try:
            return {
                'running': not self.client.is_shutting_down(),
                'suspended': self.client.is_suspended(),
                'suspended_until': self.client.suspended_until,
                'shutdown_flag': self.client.shutdown_flag,
                'fast_shutdown': self.client.fast_shutdown,
                'thread_interruptable': self.client.thread_interruptable
            }
        except Exception as e:
            Out.error(f"ClientAPI: Failed to get client status: {e}")
            return {'error': str(e)}
    
    def get_cache_info(self) -> dict:
        """Get cache information.
        
        Returns:
            Dictionary with cache information
        """
        try:
            cache_handler = self.client.get_cache_handler()
            if cache_handler:
                return {
                    'cache_count': cache_handler.get_cache_count(),
                    'cache_size': cache_handler.get_cache_size(),
                    'cache_dir': str(cache_handler.get_cache_dir())
                }
            else:
                return {'error': 'Cache handler not available'}
        except Exception as e:
            Out.error(f"ClientAPI: Failed to get cache info: {e}")
            return {'error': str(e)}
