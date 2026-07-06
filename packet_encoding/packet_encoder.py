"""Encodes windowed packet CSVs into the SN P symbol stream — one line per (window, device).

Each attacker packet becomes a single symbol, and each (window, device) substream ends with
a ``5``. Only attacker packets (those addressed to the server port) are encoded; the victim's
replies are skipped so the victim is never mistaken for a separate source. The simulator then
feeds device *i* to input neuron *i*, so the number of devices must equal its ``--input-sources``.

Symbol scheme:
  ``1`` Other          — anything that is not a pure SYN or a pure ACK
  ``2`` Anomalous SYN  — a SYN from a spoofed RFC 5737 source address
  ``3`` Normal SYN     — a SYN from an ordinary source address
  ``4`` ACK
  ``5`` end of one (window, device) substream
"""

import os
import sys
import csv
import argparse
import collections
from dataclasses import dataclass
import re

# This script lives in packet_encoding/ but shares logger.py with the repo root. When it is run
# standalone (python packet_encoding/packet_encoder.py ...) that root is not on the import path,
# so add it before importing the shared logger.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from logger import Log  # noqa: E402

ENCODE_OTHER = "1"
ENCODE_ANOMALOUS_SYN = "2"
ENCODE_NORMAL_SYN = "3"
ENCODE_ACK = "4"
END_OF_SUBSTREAM = "5"


@dataclass
class Config:
    """Where the windowed CSVs live. ``dir_name`` and ``file_path`` are derived by the encoder."""

    dir_path: str
    dir_name: str = ""
    file_path: str = ""
    target_port: int = 8080  # packets addressed to this port are attacker-originated


def parse_args() -> Config:
    parser = argparse.ArgumentParser(
        description="Encode windowed packet CSVs into the SN P symbol stream.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python packet_encoder.py some_windowed_dir""",
    )
    parser.add_argument(
        "dir_path", help="Directory of windowed_packets-*.csv files to encode."
    )
    args = parser.parse_args()
    return Config(dir_path=args.dir_path)


class PacketEncoder:
    """Reads the windowed CSVs in a directory and writes their encoded symbol stream.

    The output is written to ``encoded-<dir_name>.txt`` inside that same directory.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._config.dir_name = os.path.basename(os.path.normpath(config.dir_path))
        self._config.file_path = os.path.join(
            config.dir_path, f"encoded-{self._config.dir_name}.txt"
        )

    def _window_files(self) -> list[str]:
        """The window CSVs in ``dir_path``, ordered by their window index.

        Discovered by listing the directory rather than reconstructing file names, so the
        directory may be named anything (it need not match the original capture).
        """
        names = [
            name
            for name in os.listdir(self._config.dir_path)
            if name.startswith("windowed_packets") and name.endswith(".csv")
        ]

        def window_index(name: str) -> int:
            match = re.search(r"_(\d+)\.csv$", name)
            return int(match.group(1)) if match else -1

        return [
            os.path.join(self._config.dir_path, name)
            for name in sorted(names, key=window_index)
        ]

    def _is_src_spoof(self, src: str) -> bool:
        """True if the source IP is in an RFC 5737 test-net range (a spoofed address)."""
        return src.startswith(("192.0.2.", "198.51.100.", "203.0.113."))

    def _is_attacker(self, row) -> bool:
        """True for attacker-originated packets (those addressed to the server port).

        The victim's replies leave the server port, so excluding them keeps the victim from
        being counted as a separate source device.
        """
        try:
            return int(row["destination_port"]) == self._config.target_port
        except (KeyError, ValueError):
            return True

    def _symbol(self, row) -> str:
        """Map one packet to its symbol, from its TCP flags and (for a SYN) its source address."""
        flags = int(row["tcp_flags_raw"])
        if flags == 2:
            return (
                ENCODE_ANOMALOUS_SYN
                if self._is_src_spoof(row["source_ip"])
                else ENCODE_NORMAL_SYN
            )
        if flags == 16:
            return ENCODE_ACK
        return ENCODE_OTHER

    def _discover_devices(self) -> list[str]:
        """Every attacker device (source MAC) seen across the capture, in stable sorted order.

        Sorting fixes the device → input-neuron assignment, so device *i* always maps to neuron *i*.
        """
        devices: set[str] = set()
        for window_path in self._window_files():
            with open(window_path) as f:
                for row in csv.DictReader(f):
                    if self._is_attacker(row):
                        devices.add(row.get("device", ""))
        return sorted(devices)

    def encode_packets(self) -> None:
        """Write one encoded line per (window, device): the device's symbols, then a ``5``.

        Devices appear in the fixed order from ``_discover_devices``; a device that is idle in a
        window contributes just its end marker.
        """
        devices = self._discover_devices()
        Log.info(f"Attacker devices ({len(devices)}): {devices}")
        with open(self._config.file_path, "w+") as out:
            for window_path in self._window_files():
                by_device: dict[str, list] = collections.defaultdict(list)
                with open(window_path) as f:
                    for row in csv.DictReader(f):
                        if self._is_attacker(row):
                            by_device[row.get("device", "")].append(row)
                for device in devices:
                    for row in by_device.get(device, []):
                        out.write(self._symbol(row))
                    out.write(END_OF_SUBSTREAM + "\n")


def main() -> None:
    PacketEncoder(parse_args()).encode_packets()


if __name__ == "__main__":
    main()
