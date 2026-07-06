"""Builds a per-source SN P SYN-flood detector for n parallel sources.

Topology: per-source counting neurons fan out to both a per-source
RatioDetector_i -> RatioOR AND a shared aggregate RateDetector /
PatternDetector. Semantics:

  - RATIO  = PER-SOURCE SYN:ACK proportion (S/(S+A) > threshold), OR'd across sources.
             This is the only feature whose verdict depends on the source split
             (it isolates one half-open source the aggregate would dilute away).
  - RATE   = AGGREGATE velocity: total SYN (symbols 2+3) across sources >= K.
  - PATTERN= AGGREGATE bogon count: total anomalous SYN (symbol 2) >= P.

The three feature neurons (RateDetector, RatioOR, PatternDetector) feed a small voting
layer that turns them into a single alarm:

  - Each feature first passes through a one-shot FLAG neuron (RateFlag / RatioFlag /
    PatternFlag). The detectors are white-hole rules, so a busy window can make one fire
    several times; the flag collapses any number of firings into a single spike, so the
    vote can't mistake one loud feature for several (see RuleMaker.make_flag_rules).
  - A DECISION neuron then votes over those clean flags. By default the flags are weighted
    equally (1 each) and it fires at >= 2 -- a flat 2-of-3 majority: any two features
    agreeing raise the alarm, and no single feature raises it alone. (A lone ratio trip is
    ambiguous at low volume -- a client retrying a dead service, or a handshake whose ACK
    lands in the next window, looks identical to a stealthy half-open source -- so we require
    corroboration.) Raising `ratio_weight` to 2 instead makes the same machinery a
    ratio-anchored vote, where ratio alarms on its own (`ratio OR (rate AND pattern)`); we
    keep that as a documented alternative. The weights and threshold are parameters, left for
    the RQ3 sweep to tune.

Decision -> Output, so the Output neuron carries the alarm. The three feature verdicts are
still read individually off RateDetector / RatioOR / PatternDetector.

Per-source RatioDetector_i constants (H = max packets one source per window):
  init = ratio*H ; SYN_i +(base-ratio) ; ACK_i -ratio ;
  StreamEnd_i finalize +(base-ratio)*H ; fire at base*H + 1  (strict > ratio/base).
Mid-stream max = base*H < threshold => no premature fire; floor 0 => never negative.

Each per-source neuron sees exactly one source's symbol stream (synapse weight 1),
so the rules are trivial per-symbol -- no base-6 packing.
"""

from typing import Any
from rulemaker import RuleMaker

# Every per-source neuron sees a single source's stream, so rule generation is
# single-input (no base-6 packing): a RuleMaker with n_inputs=1 is all we need.
_RM = RuleMaker(1)


def _neuron(nid: str, content: Any, rules: list[str]) -> dict[str, Any]:
    return {
        "id": nid,
        "type": "regular",
        "content": str(content),
        "rules": rules,
        "position": {"x": 0.0, "y": 0.0},
    }


def build_system(
    n: int,
    base: int = 100,
    ratio: int = 70,
    rate_K: int = 60,
    pattern_P: int = 3,
    H: int = 600,
    ratio_weight: int = 1,
    rate_weight: int = 1,
    pattern_weight: int = 1,
    decision_threshold: int = 2,
) -> dict[str, Any]:
    # The defaults ARE the evaluation's validated thresholds (simulator.Config carries the same
    # values for the runtime CLI -- keep the two in step). So build_system(n) reproduces exactly
    # the detector the evaluation runs, which is what the showcase exporters dump.
    syn_w = base - ratio  # +per SYN  (-> RatioDetector_i)
    ack_w = -ratio  # -per ACK  (-> RatioDetector_i)
    init = ratio * H  # non-negative offset
    finalize = (base - ratio) * H  # StreamEnd_i finalize
    ratio_rule = _RM.make_proportion_detector_rules(
        H, base
    )  # fire at base*H + 1 (strict)

    neurons: list[dict[str, Any]] = []
    synapses: list[dict[str, Any]] = []

    for i in range(1, n + 1):
        neurons += [
            {
                "id": f"Packets_{i}",
                "type": "input",
                "content": "5",
                "position": {"x": 0.0, "y": 0.0},
            },
            _neuron(f"AnomalousSYN_{i}(2)", 0, _RM.make_symbol_rules(2)),
            _neuron(f"NormalSYN_{i}(3)", 0, _RM.make_symbol_rules(3)),
            _neuron(f"NormalACK_{i}(4)", 0, _RM.make_symbol_rules(4)),
            _neuron(f"StreamEndDetector_{i}", 0, _RM.make_symbol_rules(5)),
            _neuron(f"RatioDetector_{i}", init, ratio_rule),
        ]
        synapses += [
            {"from": f"Packets_{i}", "to": f"AnomalousSYN_{i}(2)", "weight": 1},
            {"from": f"Packets_{i}", "to": f"NormalSYN_{i}(3)", "weight": 1},
            {"from": f"Packets_{i}", "to": f"NormalACK_{i}(4)", "weight": 1},
            {"from": f"Packets_{i}", "to": f"StreamEndDetector_{i}", "weight": 1},
            # per-source ratio
            {
                "from": f"AnomalousSYN_{i}(2)",
                "to": f"RatioDetector_{i}",
                "weight": syn_w,
            },
            {"from": f"NormalSYN_{i}(3)", "to": f"RatioDetector_{i}", "weight": syn_w},
            {"from": f"NormalACK_{i}(4)", "to": f"RatioDetector_{i}", "weight": ack_w},
            {
                "from": f"StreamEndDetector_{i}",
                "to": f"RatioDetector_{i}",
                "weight": finalize,
            },
            {"from": f"RatioDetector_{i}", "to": "RatioOR", "weight": 1},
            # aggregate rate (velocity) + pattern
            {"from": f"AnomalousSYN_{i}(2)", "to": "RateDetector", "weight": 1},
            {"from": f"NormalSYN_{i}(3)", "to": "RateDetector", "weight": 1},
            {"from": f"AnomalousSYN_{i}(2)", "to": "PatternDetector", "weight": 1},
        ]

    neurons += [
        _neuron("RateDetector", 0, _RM.make_velocity_detector_rules(rate_K)),
        _neuron("PatternDetector", 0, _RM.make_pattern_detector_rule(pattern_P)),
        _neuron("RatioOR", 0, _RM.make_or_rules()),
        # Voting layer. Flags start pre-loaded with 2 spikes and debounce each (white-hole)
        # detector down to a single spike; Decision then votes over those flags and fires at
        # >= decision_threshold (equal weights => flat 2-of-3 majority by default).
        _neuron("RateFlag", 2, _RM.make_flag_rules()),
        _neuron("RatioFlag", 2, _RM.make_flag_rules()),
        _neuron("PatternFlag", 2, _RM.make_flag_rules()),
        _neuron("Decision", 0, _RM.make_decision_rule(decision_threshold)),
        {
            "id": "Output",
            "type": "output",
            "content": "",
            "position": {"x": 0.0, "y": 0.0},
        },
    ]
    synapses += [
        # each feature -> its one-shot flag
        {"from": "RateDetector", "to": "RateFlag", "weight": 1},
        {"from": "RatioOR", "to": "RatioFlag", "weight": 1},
        {"from": "PatternDetector", "to": "PatternFlag", "weight": 1},
        # the vote: equal weights + threshold 2 => flat 2-of-3 majority (any two features
        # agree). Set ratio_weight=2 instead for a ratio-anchored vote (ratio alarms alone).
        {"from": "RatioFlag", "to": "Decision", "weight": ratio_weight},
        {"from": "RateFlag", "to": "Decision", "weight": rate_weight},
        {"from": "PatternFlag", "to": "Decision", "weight": pattern_weight},
        {"from": "Decision", "to": "Output", "weight": 1},
    ]
    return {"neurons": neurons, "synapses": synapses}
