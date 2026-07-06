"""Windows a packet capture into fixed-Δt slices for the encoder.

Reads a capture CSV (or PCAP) and splits it into windows of width ``max_time_window`` seconds.
A window stays open a little past its boundary (``grace``) so an in-flight handshake can
finish, but a hard packet cap (``hard_limit``) guarantees it eventually closes — so a
half-open flood, whose handshakes never complete, cannot hold a window open forever. Each
window is written as ``windowed_packets-<capture>_<id>.csv``, carrying the sender's source MAC
in the ``device`` column that downstream per-source detection relies on.
"""

import csv
import os
import sys
import argparse
from dataclasses import dataclass
import re
from typing import Any
from scapy.all import PcapReader

# This script lives in packet_encoding/ but shares logger.py with the repo root. When it is run
# standalone (python packet_encoding/data_preprocessor.py ...) that root is not on the import path,
# so add it before importing the shared logger.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from logger import Log  # noqa: E402


@dataclass
class Config:
    """All configurable parameters for preprocessing data."""

    file_path: str
    dir_path: str = ""
    export_dir_path: str = ""
    target_size: int = 15  # vestigial: no longer gates the window close
    max_time_window: float = 1.0  # Δt: fixed window width in seconds
    hard_limit: int = 400  # backstop only; peak observed ~266-352 pkts/window
    grace: float = (
        0.05  # max seconds to extend past Δt to finish an in-flight handshake
    )


class Packet:
    """Represents a single network packet with the 11 fields needed for windowed output.

    Extracts and stores a subset of the original 19-column capture CSV,
    keeping only the fields relevant for SN P system encoding.
    """

    def __repr__(self) -> str:
        return ",".join(
            [
                str(self._packet_no),
                str(self._timestamp),
                str(self._source_ip),
                str(self._destination_ip),
                str(self._protocol),
                str(self._source_port),
                str(self._destination_port),
                str(self._tcp_flags_raw),
                str(self._seq_num),
                str(self._ack_num),
            ]
        )

    def __init__(self, row: dict[str | Any, Any]) -> None:
        self._packet_no: int = row["packet_no"]
        self._timestamp: float = row["timestamp"]
        self._device: str = row.get(
            "device", ""
        )  # source MAC = sending device (multi-source)
        self._source_ip: int = row["source_ip"]
        self._destination_ip: int = row["destination_ip"]
        self._protocol: str = row["protocol"]
        self._source_port: int = row["source_port"]
        self._destination_port: int = row["destination_port"]
        self._tcp_flags_raw: int = row["tcp_flags_raw"]
        self._seq_num: int = row["seq_num"]
        self._ack_num: int = row["ack_num"]

    def to_mapping(self) -> dict[str, Any]:
        """Return packet fields as a dictionary for CSV export."""
        return {
            "packet_no": self._packet_no,
            "timestamp": self._timestamp,
            "device": self._device,
            "source_ip": self._source_ip,
            "destination_ip": self._destination_ip,
            "protocol": self._protocol,
            "source_port": self._source_port,
            "destination_port": self._destination_port,
            "tcp_flags_raw": self._tcp_flags_raw,
            "seq_num": self._seq_num,
            "ack_num": self._ack_num,
        }


class WindowedPackets:
    """A sliding window of packets bounded by soft and hard limits.

    The window closes when the soft limit is met (target packet count reached,
    time window exceeded, and all pending TCP handshakes resolved) or when
    the hard limit on packet count is reached.
    """

    def __repr__(self) -> str:
        return "\n".join(map(str, self._packets))

    def __init__(self, config: Config, id: int) -> None:
        self._fieldnames = [
            "packet_no",
            "timestamp",
            "device",
            "source_ip",
            "destination_ip",
            "protocol",
            "source_port",
            "destination_port",
            "tcp_flags_raw",
            "seq_num",
            "ack_num",
        ]
        self._packets: list[Packet] = []
        self._config: Config = config
        self._max_time_window: float = float(config.max_time_window)  # = Δt
        self._window_end: float | None = (
            None  # set lazily from the first packet's timestamp
        )
        self._grace: float = float(config.grace)
        self._id: int = id
        self._pending_handshakes: dict[int, int] = {}

    def add_packet(self, row: dict[str | Any, Any]) -> bool:
        """Add a packet to this window. Returns False if the window is full."""
        if (
            self._soft_limit(float(row["timestamp"]))
            or len(self._packets) >= self._config.hard_limit
        ):
            Log.debug("Limit reached!")
            return False

        if row["is_rst"] == "True" or row["is_fin"] == "True":
            return True

        # Track SYN-ACK packets to monitor pending handshakes
        if row["is_syn_ack"] == "True":
            Log.debug(f"Packet {row['packet_no']} is SYN-ACK: {row['is_syn_ack']}")
            self._pending_handshakes[int(row["ack_num"])] = int(row["seq_num"]) + 1

        # Match ACK packets against pending handshakes
        if row["is_ack"] == "True":
            Log.debug(f"Packet {row['packet_no']} is ACK: {row['is_ack']}")
            try:
                seq_num = self._pending_handshakes.pop(int(row["seq_num"]))
                if not (seq_num == int(row["ack_num"])):
                    Log.warning(
                        f"ACK found for SYN-ACK: {row['seq_num']} but not equal. ACK={seq_num}, SYN-ACK={row['seq_num']}"
                    )
            except KeyError:
                Log.warning(f"SYN-ACK not found for ACK with SQN: {row['seq_num']}")

        self._packets.append(Packet(row))
        Log.debug(f"Successfully added packet. Total packets={len(self._packets)}")
        return True

    def _soft_limit(self, timestamp: float) -> bool:
        """Close the window once the fixed Δt has elapsed.

        Δt windows make per-window SYN count proportional to velocity. We allow a
        brief `grace` extension past the boundary so an in-flight handshake can
        complete (keeping its SYN and final ACK in the same window for the ratio
        feature), but force the close at Δt + grace so a half-open SYN flood —
        whose SYN-ACKs are never ACKed — cannot hold the window open indefinitely.
        """
        if self._window_end is None:
            self._window_end = timestamp + self._max_time_window
            Log.debug(f"Window end set: {self._window_end}")
        if timestamp < self._window_end:
            return False
        Log.debug(
            f"Pending handshakes: {self._pending_handshakes}, {len(self._pending_handshakes)}"
        )
        return (
            len(self._pending_handshakes) <= 0
            or timestamp >= self._window_end + self._grace
        )

    def export_csv(self) -> None:
        """Export this window's packets to a CSV file named {file_name}_{id}.csv."""
        if not self._packets:
            Log.info("No packets to export.")

        if not self._config.dir_path:
            re_file = re.findall(r"(?!.*\\|.*\/).+", self._config.file_path)
            file = re_file[0] if re_file else ""
            self._config.dir_path = os.path.join(
                os.path.dirname(self._config.file_path), file.removesuffix(".csv")
            )

        file_name = re.findall(r"(?!.*\\|.*\/).+", self._config.file_path)
        file_name = (
            f"windowed_packets-{file_name[0].removesuffix('.csv')}_{self._id}.csv"
            if file_name
            else f"windowed_packets_{self._id}.csv"
        )
        dir_path = (
            self._config.export_dir_path
            if self._config.export_dir_path
            else self._config.dir_path
        )
        file_path = os.path.join(dir_path, file_name)

        try:
            os.mkdir(dir_path)
        except FileExistsError:
            pass

        with open(file_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=self._fieldnames)
            w.writeheader()

            for _, packet in enumerate(self._packets):
                row = packet.to_mapping()
                w.writerow(row)

        Log.info(f"CSV saved: {file_path}")


class DataPreprocessor:
    """Orchestrates the windowing pipeline: reads a capture CSV and splits it into windows."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._windowed: list[WindowedPackets] = []

    def parse_file(self) -> None:
        if self._config.file_path.endswith(".csv"):
            self._parse_csv()
        elif self._config.file_path.endswith(".pcap"):
            self._parse_pcap()
        else:
            Log.error("File extension is not supported!", self._config.file_path)

    def _make_packet(self, count: int, packet) -> dict[str, Any]:
        tcp = packet["TCP"]
        ip = packet["IP"]
        syn = bool(tcp.flags.S)
        ack = bool(tcp.flags.A)
        fin = bool(tcp.flags.F)
        rst = bool(tcp.flags.R)

        return {
            "packet_no": count,
            "timestamp": (packet.time - self._start_time),
            "source_ip": ip.src,
            "destination_ip": ip.dst,
            "protocol": "TCP",
            "source_port": tcp.sport,
            "destination_port": tcp.dport,
            "tcp_flags_raw": int(tcp.flags),
            "seq_num": tcp.seq,
            "ack_num": tcp.ack,
            "is_syn": str(syn and not ack),
            "is_syn_ack": str(syn and ack),
            "is_ack": str(ack and not syn and not fin and not rst),
            "is_fin": str(fin),
            "is_rst": str(rst),
        }

    def _parse_pcap(self) -> None:
        """Read the input PCAP and distribute packets across windows."""
        with PcapReader(self._config.file_path) as f:
            windowed_packet = self._init_window_packet()
            self._start_time: float = 0
            count = 0
            for packet in f:
                if not self._start_time:
                    self._start_time = packet.time
                if not packet.haslayer("TCP"):
                    continue
                if not windowed_packet.add_packet(self._make_packet(count, packet)):
                    windowed_packet = self._init_window_packet()
                    windowed_packet.add_packet(self._make_packet(count, packet))
                count += 1

    def _parse_csv(self) -> None:
        """Read the input CSV and distribute packets across windows."""
        with open(self._config.file_path, newline="") as f:
            r = csv.DictReader(f)
            windowed_packet = self._init_window_packet()
            for row in r:
                if not windowed_packet.add_packet(row):
                    windowed_packet = self._init_window_packet()
                    windowed_packet.add_packet(row)

    def export_all(self) -> None:
        """Export all windows to individual CSV files."""
        for windowed_packet in self._windowed:
            windowed_packet.export_csv()

    def _init_window_packet(self) -> WindowedPackets:
        id = len(self._windowed)
        windowed_packet = WindowedPackets(self._config, id)
        self._windowed.append(windowed_packet)
        Log.info(f"Initialized new WindowedPackets with ID = {id}")
        return windowed_packet


def parse_args() -> Config:
    parser = argparse.ArgumentParser(
        description="Data Preprocessing and Input Windowing for SYN Flood Research",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Preprocess a CSV file named "test.csv"
  python data_preprocessor.py test.csv

  # Reconfigure the parameter for max time window, hard limit, and grace
  python data_preprocessor.py <file_path> --max-time-window <float> --hard-limit <int> --grace <float>
        """,
    )

    parser.add_argument("file_path", help="The CSV file to be preprocesed")

    parser.add_argument(
        "--export-dir-path",
        type=str,
        default="",
        help="Directory path for saving the preprocessed data",
    )

    parser.add_argument(
        "--target-size",
        type=int,
        default=15,
        help="Target size for soft limit before windowing the packets (default: 15)",
    )

    parser.add_argument(
        "--max-time-window",
        type=float,
        default=1.0,
        help="Delta-t: fixed window width in seconds (default: 1.0)",
    )

    parser.add_argument(
        "--hard-limit",
        type=int,
        default=400,
        help="Backstop cap on packets per window if the time boundary is not reached (default: 400)",
    )

    parser.add_argument(
        "--grace",
        type=float,
        default=0.05,
        help="Max seconds to extend a window past Delta-t to finish an in-flight handshake (default: 0.05)",
    )

    args = parser.parse_args()

    re_file = re.findall(r"(?!.*\\|.*\/).+", args.file_path)
    file = re_file[0] if re_file else ""
    dir_path = os.path.join(os.path.dirname(args.file_path), file.removesuffix(".csv"))

    config = Config(
        file_path=args.file_path,
        dir_path=dir_path,
        export_dir_path=args.export_dir_path,
        target_size=args.target_size,
        max_time_window=args.max_time_window,
        hard_limit=args.hard_limit,
        grace=args.grace,
    )
    return config


def main():
    config = parse_args()
    preprocessor = DataPreprocessor(config)
    preprocessor.parse_file()
    preprocessor.export_all()
    return


if __name__ == "__main__":
    main()
