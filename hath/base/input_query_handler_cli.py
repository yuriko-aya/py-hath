"""
Command-line input query handler for Hentai@Home Python Client.
"""

import sys
from typing import Optional


class InputQueryHandlerCLI:
    """Handles command-line input queries."""
    
    def __init__(self):
        """Initialize the CLI input handler."""
        pass
    
    def query_string(self, query_text: str) -> Optional[str]:
        """Query the user for a string input."""
        try:
            response = input(f"{query_text}: ")
            return response.strip() if response else None
        except (EOFError, KeyboardInterrupt):
            print("\nInterrupted")
            from .settings import Settings
            client = Settings.get_active_client()
            if client:
                client.shutdown()
            sys.exit(0)
        except Exception:
            return None
