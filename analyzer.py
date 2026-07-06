"""Scores a simulated run against its expected label.

``Analyzer`` reads the per-window decision histories that ``simulator.py`` produced (the
``decision_history*.csv`` files), checks whether the rate, ratio and pattern detector
neurons ever fired — and whether the ``Decision`` neuron raised the combined ``alarm`` —
and writes the verdict, expected versus observed, to ``output-<file_name>.json``.

The three features are independent views of the traffic; ``alarm`` is the flat 2-of-3
majority vote over them that the ``Decision`` neuron computes (see ``per_source_builder``):
it fires when at least two of the three features agree.
"""

import csv
from dataclasses import dataclass
import argparse
import json
import os
import re
from typing import Any
from logger import Log


@dataclass
class Config:
    """Where the decision histories live, plus the expected (rate, ratio, pattern) label to score against."""

    file_name: str
    dir_path: str = ""
    export_dir_path: str = ""
    rate: bool = False
    ratio: bool = False
    pattern: bool = False
    alarm: bool = False


def parse_args() -> Config:
    parser = argparse.ArgumentParser(
        description="Score SN P decision histories against an expected SYN-flood label.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python analyzer.py decision_history --dir-path ./run --rate True""",
    )
    parser.add_argument(
        "file_name", help="Base name of the decision-history CSV(s) to score."
    )
    parser.add_argument(
        "--dir-path", type=str, default="", help="Directory containing the CSV(s)."
    )
    parser.add_argument(
        "--export-dir-path",
        type=str,
        default="",
        help="Directory to write the verdict JSON into.",
    )
    # NOTE: type=bool treats any non-empty value as True; pass the flag only for an expected-True feature.
    parser.add_argument(
        "--rate", type=bool, default=False, help="Expected rate verdict."
    )
    parser.add_argument(
        "--ratio", type=bool, default=False, help="Expected ratio verdict."
    )
    parser.add_argument(
        "--pattern", type=bool, default=False, help="Expected pattern verdict."
    )
    parser.add_argument(
        "--alarm",
        type=bool,
        default=False,
        help="Expected alarm verdict (the Decision vote).",
    )
    args = parser.parse_args()

    return Config(
        dir_path=args.dir_path,
        file_name=args.file_name,
        rate=args.rate,
        ratio=args.ratio,
        pattern=args.pattern,
        alarm=args.alarm,
        export_dir_path=args.export_dir_path,
    )


class Analyzer:
    """Reads decision histories, detects which features fired, and records the expected-vs-observed verdict."""

    def __init__(self, config: Config) -> None:
        self._dir_path = config.dir_path
        self._export_dir_path = config.export_dir_path
        self._file_name = config.file_name
        self._rate = config.rate
        self._ratio = config.ratio
        self._pattern = config.pattern
        self._alarm = config.alarm

    def _check_feature(self, row: dict[str, Any]) -> None:
        """Mark a feature (or the alarm) as fired if its neuron spiked (a ``…a;0`` rule) in this row.

        Ratio is read from ``RatioOR``, the OR over the per-source ``RatioDetector_i`` neurons;
        the combined alarm is read from the ``Decision`` neuron's majority vote.
        """
        if re.match(r".*a;0", row["RateDetector"]):
            self._features["rate"] = True
        if re.match(r".*a;0", row.get("RatioOR", "")):
            self._features["ratio"] = True
        if re.match(r".*a;0", row["PatternDetector"]):
            self._features["pattern"] = True
        if re.match(r".*a;0", row.get("Decision", "")):
            self._features["alarm"] = True

    def start(self) -> None:
        """Score every matching decision-history CSV and write ``output-<file_name>.json``."""
        self._features = {
            "rate": False,
            "ratio": False,
            "pattern": False,
            "alarm": False,
        }

        if self._dir_path:
            files = [
                f
                for f in os.listdir(self._dir_path)
                if re.match("^" + self._file_name + ".*", f)
            ]
            Log.info("Checking directory...")
            Log.debug("Files: ", files)
            Log.info("Comparing...")
            for f in files:
                with open(os.path.join(self._dir_path, f)) as history:
                    for row in csv.DictReader(history):
                        self._check_feature(row)
        else:
            with open(f"./{self._file_name}.csv") as history:
                for row in csv.DictReader(history):
                    self._check_feature(row)

        Log.info("Results:")
        Log.info(f"Rate: {self._rate} vs {self._features['rate']}")
        Log.info(f"Ratio: {self._ratio} vs {self._features['ratio']}")
        Log.info(f"Pattern: {self._pattern} vs {self._features['pattern']}")
        Log.info(f"Alarm: {self._alarm} vs {self._features['alarm']}")

        dir_path = self._export_dir_path if self._export_dir_path else self._dir_path
        try:
            os.mkdir(dir_path)
        except FileExistsError:
            pass

        result: dict[str, Any] = {
            "expected": {
                "rate": self._rate,
                "ratio": self._ratio,
                "pattern": self._pattern,
                "alarm": self._alarm,
            },
            "result": {
                "rate": self._features["rate"],
                "ratio": self._features["ratio"],
                "pattern": self._features["pattern"],
                "alarm": self._features["alarm"],
            },
        }
        with open(
            os.path.join(dir_path, f"output-{self._file_name}.json"), "w+"
        ) as out:
            out.write(json.dumps(result))


def main() -> None:
    analyzer = Analyzer(parse_args())
    analyzer.start()


if __name__ == "__main__":
    main()
