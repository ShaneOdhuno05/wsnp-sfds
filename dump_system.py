"""Dump the per-source detector to the engine's own (builder-format) JSON.

This writes the system exactly as ``per_source_builder.build_system`` assembles it and as the
simulator POSTs it to the engine: neurons with their rules and weighted synapses, in the
simulator's rule syntax. It is a static reference of the runnable detector — nothing loads it
at runtime (the simulator builds the system in memory), so regenerate it with this script
whenever the builder changes. For the same system in the visual simulator's dialect instead,
see ``websnapse_export.py``.

Usage (from the Methodology/ directory):
    python dump_system.py [--sources N] [--out FILE]
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # importable from any directory
from per_source_builder import build_system  # noqa: E402 — its defaults are the eval thresholds


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Dump the per-source detector to builder-format JSON."
    )
    parser.add_argument(
        "--sources",
        type=int,
        default=3,
        help="Number of source chains to build (default: 3).",
    )
    parser.add_argument(
        "--out",
        default="SFDS-v3-multisource.json",
        help="Output file, relative to this script unless absolute (default: SFDS-v3-multisource.json).",
    )
    args = parser.parse_args()

    system = build_system(n=args.sources)
    out_path = args.out if os.path.isabs(args.out) else os.path.join(HERE, args.out)
    with open(out_path, "w") as f:
        json.dump(system, f, indent=2)

    print(
        f"Wrote {len(system['neurons'])} neurons / {len(system['synapses'])} synapses to {out_path}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
