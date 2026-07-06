"""Threshold sweep for the detector (research question 3).

Runs every reference capture through the detector across a range of thresholds for each feature,
then summarises detection quality (accuracy, recall, precision, false-positive rate, F1) per
threshold into ``results_<feature>.csv`` — and plots each metric if matplotlib is available. It
reuses ``simulator.SNPSimulator`` for every (capture, threshold) pair, so the SN P engine must be
running.

Each capture's expected (rate, ratio, pattern) label is read from ``scenarios.json`` by matching
the capture's filename to its scenario, so there is no separate labels file to keep aligned. With
no arguments it sweeps the reference captures in ``traffic_generation/experiments``:

    uvicorn snp_engine.main:app --port 8000      # in one terminal
    python n_simulator.py                        # in another
"""

from dataclasses import dataclass
import argparse
import json
import os
import re
import threading
from simulator import Config as SimulatorConfig, SNPSimulator

HERE = os.path.dirname(os.path.abspath(__file__))

# A scenario's `expected` list names the features that should fire; this maps each name to its
# slot in the (rate, ratio, pattern) label triple (the same mapping verify.py uses).
FEATURE_SLOT = {"syn_packet_rate": 0, "syn_ack_ratio": 1, "anomalous_syn_pattern": 2}


@dataclass
class Config:
    """Inputs for a sweep: the captures directory, scenarios.json (for labels), and the per-feature threshold ranges."""

    dir_path: str
    scenarios_path: str
    skip_simulation: bool = False
    api: str = "http://localhost:8000"
    export_filename: str = "decision_history"
    input_sources: int = 3
    target_size: int = 15
    max_time_window: float = 1.0  # Delta-t window width (seconds)
    hard_limit: int = 600  # per-window packet backstop (multi-source peak ~488)
    pattern_range: tuple[int, int] = (
        1,
        10,
    )  # bogon-SYN count/window; perfect-accuracy gap [1,7]
    rate_range: tuple[int, int] = (
        20,
        100,
    )  # total SYN/window;       perfect-accuracy gap [41,94]
    ratio_range: tuple[int, int] = (
        50,
        90,
    )  # proportion %;           perfect-accuracy gap [66,74]

    def configure_file_path(self) -> None:
        files: list[str] = os.listdir(self.dir_path)
        # Sorted for a deterministic order. Only the .csv captures are swept (the paired .pcap is
        # the raw form and would double-count); the tool's own results_*.csv are excluded too.
        self.file_paths = sorted(
            f
            for f in files
            if os.path.isfile(os.path.join(self.dir_path, f))
            and f.endswith(".csv")
            and not f.startswith("results_")
        )

    def configure_results(self) -> None:
        """Derive each capture's expected (rate, ratio, pattern) label from scenarios.json.

        Captures are named ``<scenario>_<timestamp>.csv`` and scenarios.json lists, per scenario,
        which features it should trip — so matching by name removes any separate labels file that
        would otherwise have to stay aligned with the capture order.
        """
        with open(self.scenarios_path) as f:
            scenarios = json.load(f)
        self.expected_rate, self.expected_ratio, self.expected_pattern = [], [], []
        for fname in self.file_paths:
            scenario = next((k for k in scenarios if fname.startswith(k + "_")), None)
            if scenario is None:
                raise Exception(
                    f"No scenario in {self.scenarios_path} matches capture {fname!r}"
                )
            label = [False, False, False]
            for feature in scenarios[scenario].get("expected", []):
                label[FEATURE_SLOT[feature]] = True
            self.expected_rate.append(label[0])
            self.expected_ratio.append(label[1])
            self.expected_pattern.append(label[2])


def parse_args() -> Config:
    parser = argparse.ArgumentParser(
        description="Threshold sweep over the reference captures, scoring each feature per threshold (RQ3).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sweep every reference capture; labels are read from scenarios.json:
  python n_simulator.py
  python n_simulator.py traffic_generation/experiments --rate-range 20-100""",
    )

    parser.add_argument(
        "dir_path",
        nargs="?",
        default=os.path.join(HERE, "traffic_generation", "experiments"),
        help="Directory of capture CSVs to sweep. (default: traffic_generation/experiments)",
    )

    parser.add_argument(
        "--scenarios",
        type=str,
        default=os.path.join(HERE, "traffic_generation", "scenarios.json"),
        help="scenarios.json giving each capture's expected label. (default: traffic_generation/scenarios.json)",
    )

    parser.add_argument(
        "--api",
        type=str,
        help="Base URL of the running SN P engine. (default: http://localhost:8000)",
    )

    parser.add_argument(
        "--export-filename",
        type=str,
        help="Filename for exporting in CSV. (default: decision_history)",
    )

    parser.add_argument(
        "--input-sources",
        type=int,
        help="Number of input neurons in the SFDS. (default: 3)",
    )

    parser.add_argument(
        "--target-size",
        type=int,
        help="Target size for soft limit before windowing the packets. (default: 15)",
    )

    parser.add_argument(
        "--max-time-window",
        type=float,
        help="Delta-t: fixed window width in seconds. (default: 1.0)",
    )

    parser.add_argument(
        "--hard-limit",
        type=int,
        help="Backstop cap on packets per window. (default: 600)",
    )

    parser.add_argument(
        "--rate-range",
        type=str,
        help="Velocity SYN-count range K (per window) to sweep, e.g. 20-100. (default: 20-100)",
    )

    parser.add_argument(
        "--ratio-range",
        type=str,
        help="Proportion percentage range to sweep, e.g. 50-90. (default: 50-90)",
    )

    parser.add_argument(
        "--pattern-range",
        type=str,
        help="Bogon-SYN count range to sweep, e.g. 1-10. (default: 1-10)",
    )

    parser.add_argument(
        "--skip-simulation",
        action="store_true",
        help="Skip the simulation phase and only summarise existing outputs in the directory.",
    )

    args = parser.parse_args()

    config = Config(dir_path=args.dir_path, scenarios_path=args.scenarios)
    config.configure_file_path()
    config.configure_results()

    if args.skip_simulation:
        config.skip_simulation = True
    if args.api:
        config.api = args.api
    if args.export_filename:
        config.export_filename = args.export_filename
    if args.input_sources:
        config.input_sources = args.input_sources
    if args.target_size:
        config.target_size = args.target_size
    if args.max_time_window:
        config.max_time_window = args.max_time_window
    if args.hard_limit:
        config.hard_limit = args.hard_limit
    if args.rate_range:
        rng = list(map(int, args.rate_range.split("-")))
        config.rate_range = (rng[0], rng[1])
    if args.ratio_range:
        rng = list(map(int, args.ratio_range.split("-")))
        config.ratio_range = (rng[0], rng[1])
    if args.pattern_range:
        rng = list(map(int, args.pattern_range.split("-")))
        config.pattern_range = (rng[0], rng[1])

    return config


class NSimulator:
    """Sweeps each feature's threshold over all captures and summarises detection quality per threshold."""

    def __init__(self, config: Config) -> None:
        self._base_config: SimulatorConfig = self._init_config(config)
        self._skip_simulation: bool = config.skip_simulation
        self._dir_path: str = config.dir_path
        self._file_paths: list[str] = config.file_paths
        self._export_filename: str = config.export_filename
        self._expected_rate: list[bool] = config.expected_rate
        self._expected_ratio: list[bool] = config.expected_ratio
        self._expected_pattern: list[bool] = config.expected_pattern
        self._rate_range: range = range(config.rate_range[0], config.rate_range[1] + 1)
        self._ratio_range: range = range(
            config.ratio_range[0], config.ratio_range[1] + 1
        )
        self._pattern_range: range = range(
            config.pattern_range[0], config.pattern_range[1] + 1
        )
        self._rate_stats = {
            "accuracy": [],
            "recall": [],
            "precision": [],
            "false_positive_rate": [],
            "f1_score": [],
        }
        self._ratio_stats = {
            "accuracy": [],
            "recall": [],
            "precision": [],
            "false_positive_rate": [],
            "f1_score": [],
        }
        self._pattern_stats = {
            "accuracy": [],
            "recall": [],
            "precision": [],
            "false_positive_rate": [],
            "f1_score": [],
        }

    def _make_config(self) -> SimulatorConfig:
        return SimulatorConfig(
            system_json=self._base_config.system_json,
            api=self._base_config.api,
            export_filename=self._base_config.export_filename,
            input_sources=self._base_config.input_sources,
            target_size=self._base_config.target_size,
            max_time_window=self._base_config.max_time_window,
            hard_limit=self._base_config.hard_limit,
        )

    def _init_config(self, config: Config) -> SimulatorConfig:
        return SimulatorConfig(
            system_json="per-source",  # vestigial; the system is built in memory by per_source_builder
            api=config.api,
            export_filename=config.export_filename,
            input_sources=config.input_sources,
            target_size=config.target_size,
            max_time_window=config.max_time_window,
            hard_limit=config.hard_limit,
        )

    def _make_path(self, path: str) -> None:
        try:
            os.mkdir(path)
        except:
            pass

    def _simulate_feature(self, name: str, feature_range: range) -> None:
        """Sweep one feature's threshold over every capture, writing each run's outputs under name/<threshold>/."""
        feature_dir_path = os.path.join(self._dir_path, name)
        self._make_path(feature_dir_path)
        threads: list[threading.Thread] = []
        for threshold in feature_range:
            if threads:
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
            threshold_dir_path = os.path.join(feature_dir_path, f"{name}_{threshold}")
            self._make_path(threshold_dir_path)
            threads = []
            for i, file_path in enumerate(self._file_paths):
                file_name = re.sub(r"(?!^.+)\..+", "", file_path)
                dir_path = os.path.join(threshold_dir_path, file_name)
                self._make_path(dir_path)
                config: SimulatorConfig = self._make_config()
                config.export_dir_path = dir_path
                if re.match("rate", name):
                    config.rate = threshold
                if re.match("ratio", name):
                    config.ratio = threshold
                if re.match("pattern", name):
                    config.pattern = threshold
                config.file_path = os.path.join(self._dir_path, file_path)
                config.expected_rate = self._expected_rate[i]
                config.expected_ratio = self._expected_ratio[i]
                config.expected_pattern = self._expected_pattern[i]
                simulator: SNPSimulator = SNPSimulator(config)
                thread = threading.Thread(target=simulator.start, daemon=True)
                threads.append(thread)

    def _get_summary(self, name: str, feature_range: range) -> None:
        """Score one feature across its threshold range: accuracy, recall, precision, FPR and F1 per threshold."""
        feature_dir_path = os.path.join(self._dir_path, name)
        accuracy: list[float] = []
        recall: list[float] = []
        precision: list[float] = []
        false_positive_rate: list[float] = []
        f1_score: list[float] = []
        for threshold in feature_range:
            threshold_dir_path = os.path.join(feature_dir_path, f"{name}_{threshold}")
            true_positive = 0
            true_negative = 0
            false_positive = 0
            false_negative = 0
            for i, file_path in enumerate(self._file_paths):
                file_name = re.sub(r"(?!^.+)\..+", "", file_path)
                dir_path = os.path.join(threshold_dir_path, file_name)
                output_file_path = os.path.join(
                    dir_path, f"output-{self._export_filename}.json"
                )
                try:
                    with open(output_file_path, "r") as f:
                        output = json.loads(f.readline())
                        if output["expected"][name] and output["result"][name]:
                            true_positive += 1
                        if not output["expected"][name] and not output["result"][name]:
                            true_negative += 1
                        if not output["expected"][name] and output["result"][name]:
                            false_positive += 1
                        if output["expected"][name] and not output["result"][name]:
                            false_negative += 1
                except:
                    config: SimulatorConfig = self._make_config()
                    config.export_dir_path = dir_path
                    if re.match("rate", name):
                        config.rate = threshold
                    if re.match("ratio", name):
                        config.ratio = threshold
                    if re.match("pattern", name):
                        config.pattern = threshold
                    config.file_path = os.path.join(self._dir_path, file_path)
                    config.expected_rate = self._expected_rate[i]
                    config.expected_ratio = self._expected_ratio[i]
                    config.expected_pattern = self._expected_pattern[i]
                    simulator: SNPSimulator = SNPSimulator(config)
                    simulator.start()
                    with open(output_file_path, "r") as f:
                        output = json.loads(f.readline())
                        if output["expected"][name] and output["result"][name]:
                            true_positive += 1
                        if not output["expected"][name] and not output["result"][name]:
                            true_negative += 1
                        if not output["expected"][name] and output["result"][name]:
                            false_positive += 1
                        if output["expected"][name] and not output["result"][name]:
                            false_negative += 1
            _accuracy = (
                float(
                    float(true_positive + true_negative)
                    / float(
                        true_positive + true_negative + false_negative + false_positive
                    )
                )
                if true_positive + true_negative + false_negative + false_positive > 0
                else 0.0
            )
            _recall = (
                float(float(true_positive) / float(true_positive + false_negative))
                if true_positive + false_negative > 0
                else 0.0
            )
            _precision = (
                float(float(true_positive) / float(true_positive + false_positive))
                if true_positive + false_positive > 0
                else 0.0
            )
            _false_positive_rate = (
                float(false_positive) / float(false_positive + true_negative)
                if false_positive + true_negative > 0
                else 0.0
            )
            _f1_score = (
                float(float(2 * _precision * _recall) / float(_precision + _recall))
                if _precision + _recall > 0
                else 0.0
            )

            accuracy.append(_accuracy)
            recall.append(_recall)
            precision.append(_precision)
            false_positive_rate.append(_false_positive_rate)
            f1_score.append(_f1_score)

        if re.match("rate", name):
            self._rate_stats = {
                "accuracy": accuracy,
                "recall": recall,
                "precision": precision,
                "false_positive_rate": false_positive_rate,
                "f1_score": f1_score,
            }
        if re.match("ratio", name):
            self._ratio_stats = {
                "accuracy": accuracy,
                "recall": recall,
                "precision": precision,
                "false_positive_rate": false_positive_rate,
                "f1_score": f1_score,
            }
        if re.match("pattern", name):
            self._pattern_stats = {
                "accuracy": accuracy,
                "recall": recall,
                "precision": precision,
                "false_positive_rate": false_positive_rate,
                "f1_score": f1_score,
            }

    def _make_plots(self, name: str, xrange: range) -> None:
        """Write results_<name>.csv for one feature and, if matplotlib is installed, plot each metric vs. threshold."""
        stats = {}
        _xrange = list(xrange)
        match name:
            case "rate":
                stats = self._rate_stats
            case "ratio":
                stats = self._ratio_stats
            case "pattern":
                stats = self._pattern_stats
        with open(os.path.join(self._dir_path, f"results_{name}.csv"), "w+") as f:
            f.write(f"t,accuracy,recall,precision,false_positive_rate,f1_score\n")
            for i, j in enumerate(xrange):
                f.write(
                    f"{j},{stats['accuracy'][i]},{stats['recall'][i]},{stats['precision'][i]},{stats['false_positive_rate'][i]},{stats['f1_score'][i]}\n"
                )
            f.close()

        # Plots are optional: the results CSV above is the primary artifact. Skip
        # gracefully if matplotlib isn't installed.
        try:
            import matplotlib.pyplot as plt
        except ImportError:
            print(
                f"[n_simulator] matplotlib not installed; wrote results_{name}.csv, skipping plots."
            )
            return

        for k in stats:
            plt.plot(_xrange, stats[k])
            title = (
                f"{name.capitalize()} {k.capitalize()} Detections"
                if re.match("correct", k)
                else f"{name.capitalize()} {re.sub('_', ' ', k).capitalize()}"
            )
            file_path = os.path.join(self._dir_path, f"{name}-{k}.png")
            plt.title(title)
            plt.xlabel("Threshold")
            plt.ylabel(
                f"{k.capitalize()} Detections"
                if re.match("correct", k)
                else re.sub("_", " ", k).capitalize()
            )
            plt.savefig(file_path)
            plt.close()

    def start(self) -> None:
        """Run the full sweep (unless skipped), summarise each feature, then write and plot the results."""
        if not self._skip_simulation:
            threads: list[threading.Thread] = []
            threads.append(
                threading.Thread(
                    target=self._simulate_feature,
                    args=("rate", self._rate_range),
                    daemon=True,
                )
            )
            threads.append(
                threading.Thread(
                    target=self._simulate_feature,
                    args=("ratio", self._ratio_range),
                    daemon=True,
                )
            )
            threads.append(
                threading.Thread(
                    target=self._simulate_feature,
                    args=("pattern", self._pattern_range),
                    daemon=True,
                )
            )
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        threads: list[threading.Thread] = []
        threads.append(
            threading.Thread(
                target=self._get_summary, args=("rate", self._rate_range), daemon=True
            )
        )
        threads.append(
            threading.Thread(
                target=self._get_summary, args=("ratio", self._ratio_range), daemon=True
            )
        )
        threads.append(
            threading.Thread(
                target=self._get_summary,
                args=("pattern", self._pattern_range),
                daemon=True,
            )
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self._make_plots("rate", self._rate_range)
        self._make_plots("ratio", self._ratio_range)
        self._make_plots("pattern", self._pattern_range)


def main():
    config = parse_args()
    nsimulator: NSimulator = NSimulator(config)
    nsimulator.start()


if __name__ == "__main__":
    main()
