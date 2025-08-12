"""
CakeSphere implementation for Hentai@Home Python client.

This handles the "still alive" tests in a separate thread,
matching the Java client's CakeSphere functionality.
"""

import threading
import time
from typing import TYPE_CHECKING

from .out import Out
from .stats import Stats
from .settings import Settings

if TYPE_CHECKING:
    from .server_handler import ServerHandler
    from .hentai_at_home_client import HentaiAtHomeClient


class CakeSphere(threading.Thread):
    """
    Handles still alive tests with the server in a separate thread.
    
    "Cake and grief counseling will be available at the conclusion of the test."
    - Reference to Portal game series, keeping the Java client's humor
    """
    
    def __init__(self, server_handler: 'ServerHandler', client: 'HentaiAtHomeClient'):
        """Initialize the CakeSphere."""
        super().__init__(daemon=True)
        self.server_handler = server_handler
        self.client = client
        self.do_resume = False
        self.name = "CakeSphere-Thread"
    
    def still_alive(self, resume: bool):
        """
        Start the still alive test.
        
        Args:
            resume: If True, this is a resume operation
        """
        # Cake and grief counseling will be available at the conclusion of the test.
        self.do_resume = resume
        
        # Start the thread if not already running
        if not self.is_alive():
            try:
                self.start()
            except RuntimeError:
                # Thread already started, create a new one
                new_sphere = CakeSphere(self.server_handler, self.client)
                new_sphere.do_resume = resume
                new_sphere.start()
    
    def run(self):
        """Execute the still alive test."""
        try:
            Out.debug(f"CakeSphere: Starting still alive test (resume={self.do_resume})")
            
            # Java: ServerResponse sr = ServerResponse.getServerResponse(...)
            # We need to call the server with resume parameter
            response = self.server_handler._get_server_response(
                self.server_handler.ACT_STILL_ALIVE, 
                {'add': 'resume' if self.do_resume else ''}
            )
            
            if response and response.get('status') == 'OK':
                # Java: sr.getResponseStatus() == ServerResponse.RESPONSE_STATUS_OK
                Out.debug("CakeSphere: Successfully performed a stillAlive test for the server.")
                # Java: Stats.serverContact();
                Stats.get_instance().server_contact()
                
            elif response is None or response.get('status') == 'NULL':
                # Java: sr.getResponseStatus() == ServerResponse.RESPONSE_STATUS_NULL
                fail_host = response.get('fail_host') if response else 'unknown'
                Settings.mark_rpc_server_failure(fail_host)
                Out.warning("CakeSphere: Failed to connect to the server for the stillAlive test. "
                           "This is probably a temporary connection problem.")
                
            else:
                # Java: sr.getResponseStatus() == ServerResponse.RESPONSE_STATUS_FAIL
                fail_code = response.get('fail_code', 'UNKNOWN')
                
                if fail_code.startswith("TERM_BAD_NETWORK"):
                    # Java: client.dieWithError(...)
                    self.client.die_with_error(
                        "Client is shutting down since the network is misconfigured; "
                        "correct firewall/forwarding settings then restart the client."
                    )
                else:
                    Out.warning(f"CakeSphere: Failed stillAlive test: ({fail_code}) - will retry later")
                    
        except Exception as e:
            Out.error(f"CakeSphere: Error during still alive test: {e}")
            # Don't crash the client, just log the error


class CakeSphereManager:
    """
    Manages CakeSphere instances to avoid thread proliferation.
    """
    
    def __init__(self):
        """Initialize the manager."""
        self._current_sphere = None
        self._lock = threading.Lock()
    
    def still_alive_test(self, server_handler: 'ServerHandler', client: 'HentaiAtHomeClient', resume: bool):
        """
        Perform a still alive test using CakeSphere.
        
        Args:
            server_handler: The server handler instance
            client: The client instance  
            resume: If True, this is a resume operation
        """
        with self._lock:
            # Create a new CakeSphere for this test
            sphere = CakeSphere(server_handler, client)
            sphere.still_alive(resume)
            self._current_sphere = sphere


# Global CakeSphere manager instance
_cake_sphere_manager = CakeSphereManager()


def get_cake_sphere_manager() -> CakeSphereManager:
    """Get the global CakeSphere manager instance."""
    return _cake_sphere_manager
