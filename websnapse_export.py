"""Export the per-source detector to the Websnapse visual-simulator JSON format.

``per_source_builder.build_system`` produces the system the engine runs, written in the
simulator's rule syntax: exact counts as ``a^{k}`` and "k or more, consume all" thresholds as
``a{N,}/a+`` or ``a^{N,}/a+``. The Websnapse visual SN P simulator reads the same neuron/synapse
structure but writes guards in a regex-style syntax — an exact count as ``a^k`` (or a bare ``a``
for one), and a "k or more, consume all" guard as ``a^{k}(a)^{\\ast}`` — and it expects real
on-screen positions. This module rewrites a built system into that form so the detector can be
opened and stepped through visually.

Only the rule syntax and the node positions change; the topology, the synapse weights, and every
rule's firing semantics are preserved. ``_self_check`` confirms each rewritten guard accepts the
same spike counts as the original before the file is written.

This produces a file for the *external* Websnapse tool and cannot be loaded here, so confirm it
opens by loading the output in Websnapse itself.

Usage (from the Methodology/ directory):
    python websnapse_export.py [--sources N] [--out FILE]
"""

import argparse
import copy
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # importable from any directory
from per_source_builder import build_system  # noqa: E402 — its defaults are the eval thresholds
from snp_engine.rule import Rule  # noqa: E402 — used only by the self-check

# Layout grid. These are arbitrary on-screen coordinates; Websnapse lets you rearrange the
# neurons after loading, so the only requirement is that no two land on the same spot. The
# columns trace the pipeline left to right: input -> counters -> per-source ratio -> aggregate
# detectors -> one-shot flags -> Decision -> output.
COLUMN = {
    "input": 0,
    "counter": 360,
    "ratio": 720,
    "aggregate": 1080,
    "flag": 1440,
    "decision": 1800,
    "output": 2160,
}
SOURCE_BAND = 640  # vertical space allotted to each source's chain
COUNTER_GAP = 150  # vertical gap between a source's four counter neurons


def _term_to_websnapse(term: str) -> str:
    """Rewrite one guard or consume term from simulator syntax into Websnapse syntax."""
    term = term.strip()
    if term == "a+":  # white-hole: one or more, consume all
        return "a(a)^{\\ast}"
    threshold = re.fullmatch(
        r"a(?:\^)?\{(\d+),\}", term
    )  # a{N,} or a^{N,}: N or more, consume all
    if threshold:
        return f"a^{{{threshold.group(1)}}}(a)^{{\\ast}}"
    exact = re.fullmatch(r"a\^\{(\d+)\}", term)  # a^{k}: exactly k
    if exact:
        k = int(exact.group(1))
        return "a" if k == 1 else f"a^{k}"
    return term  # bare "a" (exactly one) and any fall-through


def rule_to_websnapse(rule: str) -> str:
    """Rewrite a whole rule (``guard/consume -> production ; delay``) into Websnapse syntax.

    In Websnapse the consume side is written identically to the guard, so the rewritten guard is
    mirrored onto both sides. That is faithful here because every builder rule consumes either
    exactly its guard (``a^{k}/a^{k}``) or all present spikes (the white-hole ``.../a+``), and a
    mirrored guard expresses both. The production and delay (after ``\\to``) are left unchanged.
    """
    lhs, arrow, rhs = rule.partition("\\to")
    guard = _term_to_websnapse(lhs.partition("/")[0])
    return f"{guard}/{guard}{arrow}{rhs}"


def _role(neuron: dict) -> str:
    """Classify a neuron by id and type so the layout can place it in the right column."""
    nid, ntype = neuron["id"], neuron["type"]
    if ntype == "input":
        return "input"
    if ntype == "output":
        return "output"
    if nid in ("RateDetector", "PatternDetector", "RatioOR"):
        return "aggregate"
    if nid in ("RateFlag", "RatioFlag", "PatternFlag"):
        return "flag"
    if nid == "Decision":
        return "decision"
    if nid.startswith("RatioDetector_"):
        return "ratio"
    return "counter"


def _position(neuron: dict, aggregate_slots: list) -> dict:
    """Assign an (x, y) position to a neuron from its role and source index.

    Per-source neurons sit in a horizontal band per source; the shared aggregate detectors and
    the output sink get their own columns to the right. ``aggregate_slots`` accumulates the
    aggregate neurons already placed so each gets a distinct row.
    """
    role = _role(neuron)
    source = re.search(r"_(\d+)", neuron["id"])
    band = (
        (int(source.group(1)) - 1) * SOURCE_BAND
        if source and role != "aggregate"
        else 0
    )

    if role == "input":
        return {"x": COLUMN["input"], "y": band + 1.5 * COUNTER_GAP}
    if role == "counter":
        order = ("AnomalousSYN", "NormalSYN", "NormalACK", "StreamEndDetector")
        row = next(
            (i for i, prefix in enumerate(order) if neuron["id"].startswith(prefix)), 0
        )
        return {"x": COLUMN["counter"], "y": band + row * COUNTER_GAP}
    if role == "ratio":
        return {"x": COLUMN["ratio"], "y": band + 1.5 * COUNTER_GAP}
    if role == "aggregate":
        row = len(aggregate_slots)
        aggregate_slots.append(neuron["id"])
        return {"x": COLUMN["aggregate"], "y": row * COUNTER_GAP}
    if role == "flag":
        row = ("RateFlag", "RatioFlag", "PatternFlag").index(neuron["id"])
        return {"x": COLUMN["flag"], "y": row * COUNTER_GAP}
    if role == "decision":
        return {"x": COLUMN["decision"], "y": COUNTER_GAP}
    return {"x": COLUMN["output"], "y": COUNTER_GAP}  # output


def to_websnapse(system: dict) -> dict:
    """Return a copy of a built system rewritten into Websnapse format (rules and positions)."""
    exported = copy.deepcopy(system)
    aggregate_slots: list[str] = []
    for neuron in exported["neurons"]:
        if "rules" in neuron:
            neuron["rules"] = [rule_to_websnapse(rule) for rule in neuron["rules"]]
        neuron["position"] = _position(neuron, aggregate_slots)
    return exported


def _guard(rule: str) -> str:
    """Return the guard term of a rule (the part before ``/`` or ``\\to``)."""
    return rule.partition("\\to")[0].partition("/")[0].strip()


def _self_check(original: dict, exported: dict) -> None:
    """Confirm the export preserved the topology and every guard's firing behaviour.

    The synapses and the neuron ids must be untouched, and each rewritten guard must accept
    exactly the same spike counts as the original — checked at the small counts and around every
    threshold that appears in the rule. Raises ``AssertionError`` on any mismatch.
    """
    assert exported["synapses"] == original["synapses"], "synapses changed"
    assert [n["id"] for n in exported["neurons"]] == [
        n["id"] for n in original["neurons"]
    ], "neuron set changed"

    for before, after in zip(original["neurons"], exported["neurons"]):
        for old_rule, new_rule in zip(before.get("rules", []), after.get("rules", [])):
            old_bound = Rule._parse_bound(_guard(old_rule))
            new_bound = Rule._parse_bound(_guard(new_rule))
            counts = {0, 1, 2, 3, 4, 5, 6}
            for n in re.findall(r"\d+", _guard(old_rule)):
                counts.update({int(n) - 1, int(n), int(n) + 1})
            for c in counts:
                old_fires = re.match(old_bound, "a" * c) is not None
                new_fires = re.match(new_bound, "a" * c) is not None
                assert old_fires == new_fires, (
                    f"guard mismatch in {after['id']}: {old_rule!r} -> {new_rule!r} at {c} spikes"
                )

    json.dumps(exported)  # the result must be serialisable


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export the per-source detector to Websnapse JSON format."
    )
    parser.add_argument(
        "--sources",
        type=int,
        default=3,
        help="Number of source chains to build (default: 3).",
    )
    parser.add_argument(
        "--out",
        default="websnapse-multisource.json",
        help="Output file, relative to this script unless absolute (default: websnapse-multisource.json).",
    )
    args = parser.parse_args()

    system = build_system(n=args.sources)
    exported = to_websnapse(system)
    _self_check(system, exported)

    out_path = args.out if os.path.isabs(args.out) else os.path.join(HERE, args.out)
    with open(out_path, "w") as f:
        json.dump(exported, f, indent=2)

    print(
        f"Wrote {len(exported['neurons'])} neurons / {len(exported['synapses'])} synapses to {out_path}"
    )
    print(
        "Self-check passed: topology and guard semantics preserved. Load it in Websnapse to confirm it opens."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
