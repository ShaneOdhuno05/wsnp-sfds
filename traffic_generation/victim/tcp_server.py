#!/usr/bin/env python3
"""A minimal TCP server: it keeps a port open so the kernel answers incoming SYNs with SYN-ACKs.

Runs as the victim inside a network namespace (see setup_netns.sh) and is normally started by
scenario_runner.py. It accepts each connection and immediately closes it; its only job is to
let the kernel complete handshakes so the capture observes SYN-ACKs. Standard library only.
"""

import argparse
import socket
import sys
import threading
from datetime import datetime


class SimpleTCPServer:
    """
    Minimal TCP server that accepts connections and immediately closes them.
    The goal is to ensure the OS TCP stack generates SYN-ACK responses for incoming SYN packets.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        backlog: int = 1024,
        verbose: bool = False,
    ):
        self.host = host
        self.port = port
        self.backlog = backlog
        self.verbose = verbose
        self._server_socket = None
        self._running = False
        self._connections_accepted = 0
        self._lock = threading.Lock()

    def start(self):
        """Start the TCP server."""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self._server_socket.bind((self.host, self.port))
        except OSError as e:
            self._log(f"ERROR: Cannot bind to {self.host}:{self.port}: {e}")
            self._log("  Is another process using this port?")
            self._log("  On Windows, run as Administrator.")
            sys.exit(1)

        self._server_socket.listen(self.backlog)
        self._server_socket.settimeout(1.0)  # Allow periodic check for shutdown
        self._running = True

        self._log(
            f"TCP Server listening on {self.host}:{self.port} (backlog={self.backlog})"
        )
        self._log("Press Ctrl+C to stop...")
        self._log("")

        try:
            while self._running:
                try:
                    client_socket, client_addr = self._server_socket.accept()
                    # Handle in a separate thread to avoid blocking
                    t = threading.Thread(
                        target=self._handle_connection,
                        args=(client_socket, client_addr),
                        daemon=True,
                    )
                    t.start()
                except socket.timeout:
                    continue
                except OSError:
                    if self._running:
                        raise
                    break
        except KeyboardInterrupt:
            self._log("\nShutting down...")
        finally:
            self.stop()

    def stop(self):
        """Stop the server."""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass
        self._log(
            f"Server stopped. Total connections accepted: {self._connections_accepted}"
        )

    def _handle_connection(self, client_socket: socket.socket, client_addr: tuple):
        """Handle a single accepted connection."""
        with self._lock:
            self._connections_accepted += 1
            count = self._connections_accepted

        if self.verbose:
            self._log(f"  [{count}] Connection from {client_addr[0]}:{client_addr[1]}")

        try:
            client_socket.close()
        except OSError:
            pass

    def _log(self, message: str):
        """Print a timestamped log message."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] {message}")


def main():
    parser = argparse.ArgumentParser(
        description="Lightweight TCP Server for SYN Flood Detection Research",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python tcp_server.py --port 8080 --verbose
        """,
    )

    parser.add_argument(
        "--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", type=int, default=8080, help="Listen port (default: 8080)"
    )
    parser.add_argument(
        "--backlog",
        type=int,
        default=1024,
        help="TCP connection backlog size (default: 1024)",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Log each accepted connection"
    )

    args = parser.parse_args()

    server = SimpleTCPServer(
        host=args.host, port=args.port, backlog=args.backlog, verbose=args.verbose
    )

    server.start()


if __name__ == "__main__":
    main()
