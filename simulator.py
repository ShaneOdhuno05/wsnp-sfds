"""Drives one capture through the detector: preprocess, encode, simulate, score.

``SNPSimulator`` takes a capture (and its expected label), windows and encodes it via
``packet_encoding``, builds the per-source SN P system with ``per_source_builder``, POSTs each
window to the running engine (``snp_engine``, reached at ``--api``), writes the per-window
decision histories, and finally hands them to ``analyzer`` to score against the expected label.

Start the engine first (``uvicorn snp_engine.main:app --port 8000``), then run this against a
capture.
"""

import copy
import csv
from dataclasses import dataclass
import os
import random
from time import sleep
from typing import Any
import requests
import argparse
import threading
from analyzer import Config as AnalyzerConfig, Analyzer
from per_source_builder import build_system
from logger import Log
from packet_encoding.data_preprocessor import (
    Config as PreprocessorConfig,
    DataPreprocessor,
)
from packet_encoding.packet_encoder import Config as EncoderConfig, PacketEncoder


@dataclass
class Config:
    """Settings for one detector run: the engine endpoint, the capture, the detector thresholds, and the expected label."""

    system_json: str
    api: str = "http://localhost:8000"
    endpoint: str = "/simulate"
    file_path: str = ""
    method: str = "POST"
    input_path: str = ""
    export_filename: str = "decision_history"
    export_dir_path: str = ""
    input_sources: int = 3
    target_size: int = 15
    max_time_window: float = 1.0  # Delta-t window width (seconds)
    hard_limit: int = 600  # per-window packet backstop (multi-source peak ~488)
    pattern: int = 3  # bogon-SYN count threshold (per-window total across sources)
    rate: int = 60  # velocity: SYN count threshold K (per-window total; gap ~(40,89))
    ratio: int = 70  # proportion percentage (e.g. 70 => per-source S/(S+A) > 0.70)
    expected_pattern: bool = False
    expected_rate: bool = False
    expected_ratio: bool = False


def parse_args() -> Config:
    parser = argparse.ArgumentParser(
        description="Preprocess, encode, simulate and score one capture against the SYN-flood detector.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  # Score a capture, expecting (rate, ratio, pattern) = (F, T, F)
  python simulator.py --file-path capture.csv --input-sources 3 --expected-result FTF --export-dir-path run""",
    )

    parser.add_argument(
        "system_json",
        nargs="?",
        default="per-source",
        help="Retained for backward compatibility and ignored at runtime "
        "(the system is built in memory by per_source_builder). Optional.",
    )

    parser.add_argument(
        "--expected-result",
        type=str,
        default="FFF",
        help="Expected (rate, ratio, pattern) verdict as three T/F characters. (default: FFF)",
    )

    parser.add_argument(
        "--file-path", help="The CSV or PCAP capture to preprocess and score."
    )

    parser.add_argument(
        "--api",
        type=str,
        default="http://localhost:8000",
        help="Base URL of the running SN P engine.",
    )

    parser.add_argument(
        "--endpoint",
        type=str,
        default="/simulate",
        help="Engine endpoint to POST each window to.",
    )

    parser.add_argument(
        "--method",
        type=str,
        default="POST",
        help="HTTP method used to reach the engine.",
    )

    parser.add_argument(
        "--input-path",
        type=str,
        default="",
        help="Pre-encoded input file to simulate directly (skips preprocessing/encoding).",
    )

    parser.add_argument(
        "--export-filename",
        type=str,
        default="decision_history",
        help="Base filename for the exported decision-history CSVs. (default: decision_history)",
    )

    parser.add_argument(
        "--export-dir-path",
        type=str,
        default="",
        help="Directory to write windowed/encoded/decision-history outputs into.",
    )

    parser.add_argument(
        "--input-sources",
        type=int,
        default=3,
        help="Number of source devices (= input neurons); must match the capture. (default: 3)",
    )

    parser.add_argument(
        "--target-size",
        type=int,
        default=15,
        help="Vestigial windowing parameter; no longer gates the window close. (default: 15)",
    )

    parser.add_argument(
        "--max-time-window",
        type=float,
        default=1.0,
        help="Delta-t: fixed window width in seconds. (default: 1.0)",
    )

    parser.add_argument(
        "--hard-limit",
        type=int,
        default=600,
        help="Backstop cap on packets per window if the time boundary is not reached. (default: 600)",
    )

    parser.add_argument(
        "--pattern",
        type=int,
        default=3,
        help="Bogon/reserved-range SYN count (per window) to flag the pattern feature. (default: 3)",
    )

    parser.add_argument(
        "--rate",
        type=int,
        default=60,
        help="Velocity: total SYN-count threshold K (per window, summed across sources) to flag the rate feature. (default: 60)",
    )

    parser.add_argument(
        "--ratio",
        type=int,
        default=70,
        help="Proportion percentage for SYN:ACK (e.g. 70 => S/(S+A) > 70%%) to flag the ratio feature. (default: 70)",
    )

    args = parser.parse_args()

    expected_rate = args.expected_result[0] == "T"
    expected_ratio = args.expected_result[1] == "T"
    expected_pattern = args.expected_result[2] == "T"

    return Config(
        file_path=args.file_path,
        system_json=args.system_json,
        api=args.api,
        endpoint=args.endpoint,
        method=args.method,
        input_path=args.input_path,
        export_filename=args.export_filename,
        export_dir_path=args.export_dir_path,
        input_sources=args.input_sources,
        target_size=args.target_size,
        max_time_window=args.max_time_window,
        hard_limit=args.hard_limit,
        pattern=args.pattern,
        rate=args.rate,
        ratio=args.ratio,
        expected_rate=expected_rate,
        expected_ratio=expected_ratio,
        expected_pattern=expected_pattern,
    )


class SNPSimulator:
    """Runs the full per-capture pipeline: preprocess + encode, simulate on the engine, then score."""

    def __init__(self, config: Config) -> None:
        self._system_json: str = config.system_json
        self._url: str = config.api + config.endpoint
        self._method: str = config.method
        self._input_path: str = config.input_path
        self._input_neurons: list[int] = []
        self._filename: str = config.export_filename
        self._dir_path: str = config.export_dir_path
        self._input_count: int = config.input_sources
        self._hard_limit: int = config.hard_limit
        self._pattern: int = config.pattern
        self._rate: int = config.rate  # velocity: per-window SYN-count threshold K
        self._ratio: int = (
            config.ratio
        )  # SYN:ACK proportion threshold, as a percent (e.g. 70 => 70%)
        self._ratio_base: int = self._compute_ratio_base()
        self._preprocess(config)

    def _preprocess(self, config: Config) -> None:
        """Window and encode the capture (if given), and prepare the analyzer config.

        With a ``file_path`` this runs the preprocessor then the encoder, leaving
        ``_input_path`` pointing at the encoded file; with only an ``input_path`` it simulates
        that pre-encoded file directly.
        """
        if config.export_dir_path:
            os.makedirs(config.export_dir_path, exist_ok=True)

        # The alarm is the Decision neuron's flat 2-of-3 majority: at least two of the three
        # features agree. It is derived from the feature triple rather than passed in, so there
        # is one source of truth for the expected verdict.
        expected_alarm = (
            config.expected_rate + config.expected_ratio + config.expected_pattern
        ) >= 2

        if config.file_path:
            preprocessor_config: PreprocessorConfig = PreprocessorConfig(
                export_dir_path=config.export_dir_path,
                file_path=config.file_path,
                target_size=config.target_size,
                max_time_window=config.max_time_window,
                hard_limit=config.hard_limit,
            )

            preprocessor = DataPreprocessor(preprocessor_config)
            preprocessor.parse_file()
            preprocessor.export_all()
            dir_path = (
                preprocessor_config.export_dir_path
                if preprocessor_config.export_dir_path
                else preprocessor_config.dir_path
            )

            encoder_config: EncoderConfig = EncoderConfig(dir_path=dir_path)

            packet_encoder = PacketEncoder(encoder_config)
            packet_encoder.encode_packets()

            self._input_path = encoder_config.file_path

            self._analyzer_config = AnalyzerConfig(
                dir_path=encoder_config.dir_path,
                file_name=config.export_filename,
                rate=config.expected_rate,
                ratio=config.expected_ratio,
                pattern=config.expected_pattern,
                alarm=expected_alarm,
                export_dir_path=config.export_dir_path,
            )

        elif self._input_path:
            self._analyzer_config = AnalyzerConfig(
                dir_path=os.path.dirname(config.input_path),
                file_name=config.export_filename,
                rate=config.expected_rate,
                ratio=config.expected_ratio,
                pattern=config.expected_pattern,
                alarm=expected_alarm,
                export_dir_path=config.export_dir_path,
            )

    def start(self) -> None:
        """Build the system, simulate every window, then score the run if there was input."""
        self.parse_json()
        self.simulate()

        if self._input_path:
            analyzer: Analyzer = Analyzer(self._analyzer_config)
            analyzer.start()
            Log.info("Finished execution.")

    def parse_json(self) -> None:
        """Build the per-source detector in memory.

        The system is generated from ``per_source_builder`` (not loaded from a file), so
        ``n_inputs`` and every threshold is a parameter and the topology scales to any number
        of sources. ``system_json`` is kept for CLI/compat but is no longer the source of truth.
        """
        self._data = build_system(
            n=self._input_count,
            base=self._ratio_base,
            ratio=self._ratio,
            rate_K=self._rate,
            pattern_P=self._pattern,
            H=self._hard_limit,
        )
        self._input_neurons = [
            i for i, nu in enumerate(self._data["neurons"]) if nu["type"] == "input"
        ]
        Log.info(
            f"Built per-source SN P system: {self._input_count} source {'chains' if self._input_count > 1 else 'chain'}."
        )

    def simulate(self) -> None:
        """Simulate the run: one POST for a raw system, or one POST per window group for an input file.

        Windows are grouped ``input_count`` at a time so that source *i* in a window feeds input
        neuron *i*; a group short of sources is padded with the end marker ``"5"``. Groups are
        POSTed concurrently, one thread each.
        """
        if self._input_path == "":
            self._simulate_spike_train()
        else:
            try:
                self._lock = threading.Lock()
                self._histories: dict[int, list] = {}
                threads: list[threading.Thread] = []
                spike_trains: list[str] = []
                with open(self._input_path, "r") as f:
                    Log.info(f"Simulating with input file: {self._input_path}.")
                    while True:
                        row = f.readline().strip()
                        if row != "":
                            spike_trains.append(row)
                        else:
                            break

                spike_trains.reverse()
                counter = 0
                while spike_trains:
                    group: list[str] = []
                    for i in range(self._input_count):
                        if spike_trains:
                            group.append(spike_trains.pop())
                        else:
                            group.append("5")

                    t = threading.Thread(
                        target=self._t_simulate_spike_train,
                        kwargs={"count": counter, "spike_trains": group},
                        daemon=True,
                    )
                    threads.append(t)
                    counter += 1

                for t in threads:
                    t.start()

                for t in threads:
                    t.join()

                Log.info("Successfully fetch all histories.")

            except Exception as e:
                Log.error(f"An error occured: {e}")

    def _compute_ratio_base(self) -> int:
        """Smallest power of ten strictly greater than the ratio percentage.

        Maps the proportion percentage to its denominator: 70 -> 100 (R=0.70),
        705 -> 1000 (R=0.705). Drives the RatioDetector's integer SYN:ACK proportion test.
        """
        temp = 0
        base = 10
        while temp != self._ratio:
            base *= 10
            temp = self._ratio % base
        return base

    def _simulate_spike_train(self) -> None:
        """POST the bare system (no input file) once and record the returned history."""
        Log.info("Simulating...")
        match self._method:
            case "POST":
                Log.info(f"Sending POST request to {self._url}...")
                response = requests.post(url=self._url, json=self._data)
                Log.info(f"Received POST request from {self._url}.")
                Log.info("Appending history.")
                history = response.json()["history"]
                self._history_to_csv(self._filename, history, self._dir_path)
            case _:
                pass

    def _t_simulate_spike_train(self, count: int, spike_trains: list[str]) -> None:
        """Simulate one window group: load its spikes into the input neurons, POST, save the history.

        Runs in its own thread; retries once (after a short random back-off) if the request fails.
        """
        data = copy.deepcopy(self._data)
        for i, n in enumerate(self._input_neurons):
            data["neurons"][n]["content"] = spike_trains[i]

        Log.info(f"Simulating {spike_trains}...")
        match self._method:
            case "POST":
                Log.info(f"Sending POST request to {self._url}...")
                try:
                    response = requests.post(url=self._url, json=data)
                    dir = (
                        self._dir_path
                        if self._dir_path
                        else os.path.dirname(self._input_path)
                    )
                    self._history_to_csv(
                        f"{self._filename}_{count}", (response.json())["history"], dir
                    )
                except Exception:
                    sleep(random.random() * 10.0)
                    try:
                        response = requests.post(url=self._url, json=data)
                        dir = (
                            self._dir_path
                            if self._dir_path
                            else os.path.dirname(self._input_path)
                        )
                        self._history_to_csv(
                            f"{self._filename}_{count}",
                            (response.json())["history"],
                            dir,
                        )
                    except Exception:
                        Log.error(
                            f"Failed to fetch history for {self._filename}_{count}"
                        )
            case _:
                pass

    def _parse_fieldnames(self) -> list[str]:
        """CSV header for a decision history: ``Tick`` followed by every neuron id."""
        fieldnames: list[str] = ["Tick"]
        for neuron in self._data["neurons"]:
            fieldnames.append(neuron["id"])
        return fieldnames

    def _parse_row(
        self, tick: int, neurons: dict[str, dict[str, str]]
    ) -> dict[str, Any]:
        """One CSV row for a tick: the fired rule for each regular neuron, else its spike data."""
        row: dict[str, Any] = {"Tick": tick}
        for key in neurons:
            if neurons[key]["type"] == "regular":
                row[key] = neurons[key]["rule"] if neurons[key]["rule"] else "-"
            else:
                row[key] = neurons[key]["data"]

        return row

    def _history_to_csv(self, filename: str, history, dir: str = "") -> None:
        """Write a simulation history (one entry per tick) to ``<dir>/<filename>.csv``."""
        filepath = os.path.join(dir, filename + ".csv")
        with open(filepath, "w+", newline="") as f:
            Log.info(f"Writing history in {filename}...")
            w = csv.DictWriter(f, fieldnames=self._parse_fieldnames())
            w.writeheader()

            for i, neurons in enumerate(history):
                row = self._parse_row(i - 1, neurons)
                w.writerow(row)
            Log.info(f"Done writing history in {filename}.")


def main() -> None:
    config: Config = parse_args()
    simulator = SNPSimulator(config)
    simulator.start()


if __name__ == "__main__":
    main()
