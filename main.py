#!/usr/bin/env python3

"""
Hentai@Home Python Client

Copyright 2008-2024 E-Hentai.org
https://forums.e-hentai.org/
tenboro@e-hentai.org

This file is part of Hentai@Home Python Client.

Hentai@Home Python Client is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Hentai@Home Python Client is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Hentai@Home Python Client.  If not, see <https://www.gnu.org/licenses/>.
"""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def main():
    """Main entry point for the Hentai@Home client."""
    try:
        # Check for multiprocess mode flag
        multiprocess_mode = '--multiprocess' in sys.argv or '--mp' in sys.argv
        
        if multiprocess_mode:
            print("Starting Hentai@Home client in multiprocess mode...")
            from hath.base.multiprocess_client import MultiprocessHentaiAtHomeClient
            from hath.base.input_query_handler_cli import InputQueryHandlerCLI
            
            iqh = InputQueryHandlerCLI()
            client = MultiprocessHentaiAtHomeClient(iqh, sys.argv[1:])
            client.run()
        else:
            print("Starting Hentai@Home client in single-process mode...")
            from hath.base.hentai_at_home_client import HentaiAtHomeClient
            from hath.base.input_query_handler_cli import InputQueryHandlerCLI
            
            iqh = InputQueryHandlerCLI()
            client = HentaiAtHomeClient(iqh, sys.argv[1:])
            client.run()
            
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
        sys.exit(0)
    except Exception as e:
        print(f"Failed to initialize client: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
