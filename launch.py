#!/usr/bin/env python3

"""
Hentai@Home Python Client Launcher

This script provides an easy way to launch the H@H client in different modes.
"""

import sys
import argparse
from pathlib import Path

def main():
    """Main launcher function."""
    parser = argparse.ArgumentParser(
        description="Hentai@Home Python Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Start in single-process mode
  %(prog)s --multiprocess           # Start in multiprocess mode
  %(prog)s --mp                     # Start in multiprocess mode (short)
  %(prog)s --debug                  # Start with debug logging
  %(prog)s --mp --debug             # Start multiprocess with debug
  %(prog)s --help                   # Show this help message

Multiprocess Mode Benefits:
  • True parallelism (bypasses Python GIL)
  • Better CPU utilization for multi-core systems
  • Improved fault isolation between components
  • Enhanced performance for high-traffic nodes
  • Better resource management and monitoring

Single-Process Mode Benefits:
  • Lower memory overhead
  • Simpler debugging
  • Faster startup time
  • Better for low-traffic nodes
        """
    )
    
    parser.add_argument(
        '--multiprocess', '--mp',
        action='store_true',
        help='Run in multiprocess mode for better performance'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        help='Override client port'
    )
    
    parser.add_argument(
        '--cache-dir',
        type=str,
        help='Override cache directory'
    )
    
    parser.add_argument(
        '--workers',
        type=int,
        default=4,
        help='Number of HTTP workers in multiprocess mode (default: 4)'
    )
    
    args, unknown_args = parser.parse_known_args()
    
    # Build arguments for the client
    client_args = unknown_args.copy()
    
    if args.debug:
        client_args.append('--debug')
    
    if args.port:
        client_args.extend(['--port', str(args.port)])
    
    if args.cache_dir:
        client_args.extend(['--cache-dir', args.cache_dir])
    
    if args.multiprocess:
        client_args.append('--multiprocess')
        if args.workers != 4:
            client_args.extend(['--workers', str(args.workers)])
    
    try:
        # Import and run the appropriate client
        if args.multiprocess:
            print("🚀 Starting Hentai@Home Python Client in MULTIPROCESS mode")
            print(f"   Workers: {args.workers}")
            print(f"   Debug: {'Enabled' if args.debug else 'Disabled'}")
            print()
            
            from hath.base.multiprocess_client import MultiprocessHentaiAtHomeClient
            from hath.base.input_query_handler_cli import InputQueryHandlerCLI
            
            iqh = InputQueryHandlerCLI()
            client = MultiprocessHentaiAtHomeClient(iqh, client_args)
            client.run()
        else:
            print("⚡ Starting Hentai@Home Python Client in SINGLE-PROCESS mode")
            print(f"   Debug: {'Enabled' if args.debug else 'Disabled'}")
            print()
            
            from hath.base.hentai_at_home_client import HentaiAtHomeClient
            from hath.base.input_query_handler_cli import InputQueryHandlerCLI
            
            iqh = InputQueryHandlerCLI()
            client = HentaiAtHomeClient(iqh, client_args)
            client.run()
            
    except KeyboardInterrupt:
        print("\n\n👋 Shutdown requested by user")
        sys.exit(0)
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("Make sure all dependencies are installed and the client is properly set up.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Failed to initialize client: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Add the project root to Python path
    project_root = Path(__file__).parent
    sys.path.insert(0, str(project_root))
    
    main()
