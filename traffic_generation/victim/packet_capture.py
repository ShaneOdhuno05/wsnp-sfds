#!/usr/bin/env python3
"""Captures victim-side traffic with Scapy and exports it as a PCAP plus a per-packet CSV.

Runs as the victim inside a network namespace (see setup_netns.sh), normally started by
scenario_runner.py, sniffing the victim's veth interface. The CSV it writes — including each
packet's source MAC in the ``device`` column — is what the preprocessing/encoding stage
consumes. Capturing needs raw-socket access, so run it with sudo/root.

Dependencies: scapy>=2.5.0
"""

import argparse
import csv
import os
import sys
import threading
import time
from datetime import datetime

print("Initializing packet capture engine (this may take a few seconds)...")
from scapy.all import sniff, wrpcap, TCP, IP, Ether, conf, get_if_list  # type: ignore  # noqa: E402


class PacketCapture:
    """
    Captures network packets using Scapy's sniff() function,
    saves to PCAP, and exports to CSV.
    """

    def __init__(
        self,
        interface: str,
        output_dir: str = "./experiments",
        experiment_name: str = "capture",
        bpf_filter: str = "",
        verbose: bool = False,
    ):
        self.interface = interface
        self.output_dir = output_dir
        self.experiment_name = experiment_name
        self.bpf_filter = bpf_filter
        self.verbose = verbose

        self._packets = []
        self._capture_start_time: float = 0.0
        self._stop_event = threading.Event()
        self._packet_count = 0

    def start_capture(self, duration: float = 0, packet_count: int = 0):
        """
        Start packet capture.

        Args:
            duration: Capture for this many seconds (0 = until stopped).
            packet_count: Stop after this many packets (0 = unlimited).
        """
        os.makedirs(self.output_dir, exist_ok=True)

        self._log(f"Starting capture on interface '{self.interface}'")
        if self.bpf_filter:
            self._log(f"BPF filter: {self.bpf_filter}")
        if duration > 0:
            self._log(f"Duration: {duration} seconds")
        if packet_count > 0:
            self._log(f"Packet limit: {packet_count}")
        self._log("Capturing... (Press Ctrl+C to stop)")
        self._log("")

        self._capture_start_time = time.time()

        # Build sniff kwargs
        sniff_kwargs = {
            "iface": self.interface,
            "prn": self._packet_callback,
            "store": True,
            "stop_filter": lambda _: self._stop_event.is_set(),
        }

        if self.bpf_filter:
            sniff_kwargs["filter"] = self.bpf_filter

        if duration > 0:
            sniff_kwargs["timeout"] = duration

        if packet_count > 0:
            sniff_kwargs["count"] = packet_count

        try:
            captured = sniff(**sniff_kwargs)
            self._packets = list(captured)
        except KeyboardInterrupt:
            self._log("\nCapture interrupted by user.")
        except PermissionError:
            self._log(
                "ERROR: Permission denied. Run as Administrator (Windows) "
                "or root (Linux)."
            )
            sys.exit(1)
        except Exception as e:
            self._log(f"ERROR: Capture failed: {e}")
            if "Npcap" in str(e) or "pcap" in str(e).lower():
                self._log("  Make sure Npcap is installed: https://npcap.com/")
                self._log("  Check 'WinPcap API-compatible Mode' during install.")
            sys.exit(1)

        self._log(f"Capture complete. {len(self._packets)} packets captured.")

    def stop_capture(self):
        """Signal the capture to stop."""
        self._stop_event.set()

    def save_pcap(self) -> str:
        """Save captured packets to PCAP file. Returns the file path."""
        if not self._packets:
            self._log("No packets to save.")
            return ""

        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        filename = f"{self.experiment_name}_{timestamp}.pcap"
        filepath = os.path.join(self.output_dir, filename)

        wrpcap(filepath, self._packets)
        self._log(f"PCAP saved: {filepath}")
        return filepath

    def export_csv(self) -> str:
        """Export captured packets to CSV. Returns the file path."""
        if not self._packets:
            self._log("No packets to export.")
            return ""

        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        filename = f"{self.experiment_name}_{timestamp}.csv"
        filepath = os.path.join(self.output_dir, filename)

        fieldnames = [
            "packet_no",
            "timestamp",
            "timestamp_epoch",
            "device",
            "source_ip",
            "destination_ip",
            "protocol",
            "length",
            "source_port",
            "destination_port",
            "tcp_flags",
            "tcp_flags_raw",
            "seq_num",
            "ack_num",
            "window_size",
            "is_syn",
            "is_syn_ack",
            "is_ack",
            "is_fin",
            "is_rst",
        ]

        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for i, pkt in enumerate(self._packets, start=1):
                row = self._extract_packet_fields(pkt, i)
                writer.writerow(row)

        self._log(f"CSV saved:  {filepath}")
        return filepath

    def _packet_callback(self, packet):
        """Called for each captured packet during sniff."""
        self._packet_count += 1
        if self.verbose and packet.haslayer(TCP):
            self._print_packet_summary(packet, self._packet_count)

    def _print_packet_summary(self, packet, num: int):
        """Print a one-line summary of a captured packet."""
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        ip = packet[IP]
        tcp = packet[TCP]
        flags = self._flags_to_str(tcp)
        elapsed = float(packet.time) - self._capture_start_time

        print(
            f"  [{num:>5}] {elapsed:8.3f}s  "
            f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}  "
            f"[{flags}]  seq={tcp.seq}"
        )

    def _extract_packet_fields(self, packet, packet_number: int) -> dict:
        """Extract all relevant fields from a Scapy packet."""
        result = {
            "packet_no": packet_number,
            "timestamp": 0.0,
            "timestamp_epoch": float(packet.time),
            "device": "",
            "source_ip": "",
            "destination_ip": "",
            "protocol": "",
            "length": len(packet),
            "source_port": 0,
            "destination_port": 0,
            "tcp_flags": "",
            "tcp_flags_raw": 0,
            "seq_num": 0,
            "ack_num": 0,
            "window_size": 0,
            "is_syn": False,
            "is_syn_ack": False,
            "is_ack": False,
            "is_fin": False,
            "is_rst": False,
        }

        # Relative timestamp
        if self._capture_start_time:
            result["timestamp"] = round(
                float(packet.time) - self._capture_start_time, 6
            )

        # Ethernet layer -> source DEVICE (source MAC). Stable per attacker veth and
        # unaffected by IP spoofing, so it attributes each frame to its sending device.
        if packet.haslayer(Ether):
            result["device"] = packet[Ether].src

        # IP layer
        if packet.haslayer(IP):
            ip = packet[IP]
            result["source_ip"] = ip.src
            result["destination_ip"] = ip.dst
            result["protocol"] = "TCP" if packet.haslayer(TCP) else str(ip.proto)

        # TCP layer
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            result["protocol"] = "TCP"
            result["source_port"] = tcp.sport
            result["destination_port"] = tcp.dport
            result["tcp_flags_raw"] = int(tcp.flags)
            result["seq_num"] = tcp.seq
            result["ack_num"] = tcp.ack
            result["window_size"] = tcp.window

            # Human-readable flags
            result["tcp_flags"] = self._flags_to_str(tcp)

            # Boolean convenience columns
            syn = bool(tcp.flags.S)
            ack = bool(tcp.flags.A)
            fin = bool(tcp.flags.F)
            rst = bool(tcp.flags.R)

            result["is_syn"] = syn and not ack
            result["is_syn_ack"] = syn and ack
            result["is_ack"] = ack and not syn and not fin and not rst
            result["is_fin"] = fin
            result["is_rst"] = rst

        return result

    @staticmethod
    def _flags_to_str(tcp) -> str:
        """Convert TCP flags to a human-readable string."""
        flag_names = []
        if tcp.flags.S:
            flag_names.append("SYN")
        if tcp.flags.A:
            flag_names.append("ACK")
        if tcp.flags.F:
            flag_names.append("FIN")
        if tcp.flags.R:
            flag_names.append("RST")
        if tcp.flags.P:
            flag_names.append("PSH")
        if tcp.flags.U:
            flag_names.append("URG")
        return ",".join(flag_names) if flag_names else ""

    def _log(self, message: str):
        """Print a timestamped log message."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] {message}")


def list_interfaces():
    """List available network interfaces with details."""
    print("\nAvailable network interfaces:")
    print("=" * 70)

    try:
        # Try the detailed interface listing (works on Windows with Npcap)
        for iface in conf.ifaces.values():
            print(f"  Name:        {iface.name}")
            if hasattr(iface, "description") and iface.description:
                print(f"  Description: {iface.description}")
            if hasattr(iface, "ip") and iface.ip:
                print(f"  IP:          {iface.ip}")
            if hasattr(iface, "mac") and iface.mac:
                print(f"  MAC:         {iface.mac}")
            print()
    except Exception:
        # Fallback to simple listing
        for name in get_if_list():
            print(f"  {name}")
        print()

    print("Use the 'Name' value with --interface.")
    print(
        "Common names: 'veth-vic' / 'eth0' on Linux, 'Wi-Fi' / 'Ethernet' on Windows."
    )


def main():
    parser = argparse.ArgumentParser(
        description="Packet Capture and CSV Export for SYN Flood Research",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List available interfaces
  python packet_capture.py --list-interfaces

  # Capture on the victim veth for 40 seconds, TCP port 8080 only
  sudo python3 packet_capture.py --interface veth-vic --filter "tcp port 8080" --duration 40
        """,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--interface", help="Network interface to capture on")
    group.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit",
    )

    parser.add_argument(
        "--output-dir",
        default="./experiments",
        help="Directory for output files (default: ./experiments)",
    )
    parser.add_argument(
        "--experiment-name",
        default="capture",
        help="Filename prefix (default: capture)",
    )
    parser.add_argument(
        "--filter", default="", help="BPF filter string (e.g., 'tcp port 8080')"
    )
    parser.add_argument(
        "--attacker-ip", default="", help="Filter to traffic from this source IP only"
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=0,
        help="Capture duration in seconds (0 = manual stop)",
    )
    parser.add_argument(
        "--packet-count",
        type=int,
        default=0,
        help="Stop after N packets (0 = unlimited)",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Print each captured packet"
    )

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    # Build BPF filter
    bpf_filter = args.filter
    if args.attacker_ip:
        ip_filter = f"src host {args.attacker_ip}"
        if bpf_filter:
            bpf_filter = f"({bpf_filter}) and {ip_filter}"
        else:
            bpf_filter = ip_filter

    capture = PacketCapture(
        interface=args.interface,
        output_dir=args.output_dir,
        experiment_name=args.experiment_name,
        bpf_filter=bpf_filter,
        verbose=args.verbose,
    )

    capture.start_capture(
        duration=args.duration,
        packet_count=args.packet_count,
    )

    # Save outputs
    capture.save_pcap()
    capture.export_csv()


if __name__ == "__main__":
    main()
