"""Main entry point for pyiodine CLI.

This module provides the command-line interfaces for both the client (pyiodine)
and server (pyiodined) components of the iodine DNS tunneling tool.
"""

from __future__ import annotations

import argparse
import logging
import sys

from pyiodine.client import IodineClient
from pyiodine.server import IodineServer


def main_client() -> int:
    """Main entry point for pyiodine client.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    parser = argparse.ArgumentParser(
        description="pyiodine - DNS tunneling client (Python port of iodine)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pyiodine -f 192.168.1.1 test.com
  pyiodine -f -P secret 192.168.1.1 t1.example.com
  pyiodine -f -r -T txt 8.8.8.8 tunnel.example.com
        """,
    )

    parser.add_argument(
        "-f",
        "--foreground",
        action="store_true",
        help="Run in foreground (default: daemonize)",
    )
    parser.add_argument(
        "-P",
        "--password",
        metavar="PASS",
        help="Password for authentication (not recommended, use prompt instead)",
    )
    parser.add_argument(
        "-r",
        "--relay",
        action="store_true",
        help="Use raw UDP relay mode",
    )
    parser.add_argument(
        "-T",
        "--type",
        metavar="TYPE",
        default="txt",
        choices=["txt", "null", "srv", "mx", "cname", "a"],
        help="DNS record type to use (default: txt)",
    )
    parser.add_argument(
        "-R",
        "--raw-port",
        metavar="PORT",
        type=int,
        default=53,
        help="Port for raw UDP mode (default: 53)",
    )
    parser.add_argument(
        "-L",
        "--lazy",
        action="store_true",
        help="Enable lazy mode (less frequent communication)",
    )
    parser.add_argument(
        "-M",
        "--mtu",
        metavar="SIZE",
        type=int,
        help="Set MTU for tunnel interface",
    )
    parser.add_argument(
        "-m",
        "--hostname-maxlen",
        metavar="LEN",
        type=int,
        default=255,
        help="Maximum hostname length (default: 255)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        metavar="SEC",
        type=int,
        default=5,
        help="DNS query timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (use multiple times for more)",
    )
    parser.add_argument(
        "nameserver",
        nargs="?",
        help="DNS nameserver to use (optional, uses system default if not specified)",
    )
    parser.add_argument(
        "domain",
        help="Domain to use for tunneling (e.g., t1.example.com)",
    )

    args = parser.parse_args()

    # Set up logging
    log_level = logging.WARNING
    if args.verbose >= 2:
        log_level = logging.DEBUG
    elif args.verbose >= 1:
        log_level = logging.INFO

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    # Get password
    password = args.password
    if not password:
        import getpass

        password = getpass.getpass("Password: ")

    # Create and configure client
    nameserver = args.nameserver if args.nameserver else "8.8.8.8"
    client = IodineClient(
        domain=args.domain,
        nameserver=nameserver,
        password=password,
        qtype=args.type,
        lazy_mode=args.lazy,
        select_timeout=args.timeout,
        hostname_maxlen=args.hostname_maxlen,
    )

    # Connect to server
    print(f"Connecting to {args.domain} via {nameserver}...")
    if not client.connect():
        print("Failed to connect to server", file=sys.stderr)
        return 1

    print("Connected! Starting tunnel...")
    print("Tunnel IP: 10.0.0.2")

    # Run tunnel
    try:
        client.tunnel()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    finally:
        client.disconnect()

    return 0


def main_server() -> int:
    """Main entry point for pyiodined server.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    parser = argparse.ArgumentParser(
        description="pyiodined - DNS tunneling server (Python port of iodined)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pyiodined -f 10.0.0.1 t1.example.com
  pyiodined -f -P secret 192.168.99.1 tunnel.example.com
  pyiodined -f -p 5353 -u nobody 10.0.0.1 t1.example.com
        """,
    )

    parser.add_argument(
        "-f",
        "--foreground",
        action="store_true",
        help="Run in foreground (default: daemonize)",
    )
    parser.add_argument(
        "-P",
        "--password",
        metavar="PASS",
        help="Password for authentication (not recommended, use prompt instead)",
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar="PORT",
        type=int,
        default=53,
        help="DNS port to listen on (default: 53)",
    )
    parser.add_argument(
        "-u",
        "--user",
        metavar="USER",
        help="Drop privileges to this user",
    )
    parser.add_argument(
        "-t",
        "--mtu",
        metavar="MTU",
        type=int,
        default=1500,
        help="MTU for tunnel interface (default: 1500)",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug output",
    )
    parser.add_argument(
        "-c",
        "--chroot",
        metavar="DIR",
        help="Chroot to this directory after startup",
    )
    parser.add_argument(
        "ip",
        help="IP address for tunnel interface (e.g., 10.0.0.1)",
    )
    parser.add_argument(
        "domain",
        help="Domain to serve (e.g., t1.example.com)",
    )

    args = parser.parse_args()

    # Set up logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    # Get password
    password = args.password
    if not password:
        import getpass

        password = getpass.getpass("Password: ")

    # Create and configure server
    server = IodineServer(
        ip=args.ip,
        domain=args.domain,
        password=password,
        port=args.port,
        mtu=args.mtu,
        debug=args.debug,
    )

    # Run server
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    finally:
        server.stop()

    return 0


def main() -> int:
    """Main entry point - detects which command to run.

    Returns:
        Exit code.
    """
    if "pyiodined" in sys.argv[0] or "server" in sys.argv[0].lower():
        return main_server()
    else:
        return main_client()


if __name__ == "__main__":
    raise SystemExit(main())
