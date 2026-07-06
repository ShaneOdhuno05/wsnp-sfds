class RuleMaker:
    def __init__(self, n_inputs: int) -> None:
        self._n_inputs: int = n_inputs

    def make_proportion_detector_rules(self, hard_limit: int, base: int) -> list[str]:
        """Generates the threshold rule for a proportion (SYN:ACK ratio) detector.

        This is an integer SYN:ACK proportion test. With the
        non-negative offset (init = rate*H*n, finalize = (base-rate)*H*n), the
        detector's value at stream end is `base*H*n + (base-rate)*S - rate*A`, so it
        fires strictly above the proportion threshold on reaching `base*H*n + 1`.

        Args:
            hard_limit (int): per-window packet cap H (group bound is H*n_inputs).
            base (int): proportion denominator (e.g. 100 for a percentage threshold).

        Returns:
            list[str]: single white-hole threshold rule for the RatioDetector neuron.
        """
        total = hard_limit * self._n_inputs
        threshold = (base * total) + 1
        t = "{" + str(threshold) + ",}" if threshold > 1 else ""
        return [f"a{t}/a+\\to a;0"]

    def make_velocity_detector_rules(self, threshold: int) -> list[str]:
        """Rule for the AGGREGATE RateDetector neuron (velocity).

        Rate is a velocity: total SYN (symbols 2+3) summed across all sources within a
        fixed-Delta-t window. The detector fires once the accumulated SYN count reaches
        `threshold` (a per-window total; the per-source neurons already sum into it, so
        there is no n_inputs scaling here).

        Args:
            threshold (int): per-window total SYN-count threshold K.

        Returns:
            list[str]: single white-hole count rule for the RateDetector neuron.
        """
        spikes = "^{" + str(threshold) + ",}" if threshold > 1 else ""
        return [f"a{spikes}/a+\\to a;0"]

    def make_pattern_detector_rule(self, threshold: int) -> list[str]:
        """Rule for the AGGREGATE PatternDetector neuron (bogon/reserved-range count).

        Fires once the bogon-SYN (symbol 2) count summed across all sources within a
        window reaches `threshold` (a per-window total, no n_inputs scaling).

        Args:
            threshold (int): per-window total bogon-SYN count threshold P.

        Returns:
            list[str]: single white-hole count rule for the PatternDetector neuron.
        """
        spikes = "^{" + str(threshold) + ",}" if threshold > 1 else ""
        return [f"a{spikes}/a+\\to a;0"]

    def make_symbol_rules(self, symbol: int) -> list[str]:
        """Per-source counting rules: spike once on `symbol`, forget every other symbol.

        Used by the per-source counting neurons (AnomalousSYN_i / NormalSYN_i /
        NormalACK_i / StreamEndDetector_i). Each such neuron is fed by exactly one
        source's stream (synapse weight 1), so it sees a single symbol per tick and
        needs no base-6 decoding.

        Args:
            symbol (int): the encoder symbol this neuron counts (2, 3, 4 or 5).

        Returns:
            list[str]: spike-on-`symbol`, forget-otherwise rules for symbols 1..5.
        """
        rules = [f"a^{{{symbol}}}/a^{{{symbol}}}\\to a;0"]
        rules += [
            f"a^{{{s}}}/a^{{{s}}}\\to\\lambda" for s in (1, 2, 3, 4, 5) if s != symbol
        ]
        return rules

    def make_or_rules(self) -> list[str]:
        """Rule for the RatioOR neuron: spike if any per-source RatioDetector_i fired."""
        return ["a+\\to a;0"]

    def make_flag_rules(self) -> list[str]:
        """One-shot 'flag' rules: emit a single spike the first time a feature fires, then go quiet.

        Each feature detector is a white-hole rule, so on a busy window it can cross its
        threshold, consume everything, refill and fire again -- several times over. A vote
        downstream must not read those repeats as several separate features. This gate
        debounces them down to a single boolean spike.

        The neuron is pre-loaded with 2 spikes (see per_source_builder.build_system). Each
        detector firing then delivers one more:

          - First firing: 2 + 1 = 3, so the exact-match rule `a^{3}/a^{3} -> a;0` fires once,
            emits a single spike, and consumes all 3 (back to 0).
          - Every later firing: 0 + 1 = 1, so the forget rule `a^{1}/a^{1} -> lambda` discards
            it with no output.

        However many times the detector refires, then, exactly one spike reaches the vote.
        """
        return ["a^{3}/a^{3}\\to a;0", "a^{1}/a^{1}\\to\\lambda"]

    def make_decision_rule(self, threshold: int) -> list[str]:
        """Threshold rule for the Decision neuron -- the alarm vote over the one-shot flags.

        The Decision neuron sums the (optionally weighted) flags and fires once their total
        reaches `threshold`. With equal weights and a threshold of 2 this is a flat 2-of-3
        majority: any two features agreeing raise the alarm, and none raises it alone. Giving
        ratio weight 2 instead makes the same rule a ratio-anchored vote -- ratio (2) clears
        the bar by itself, i.e. `ratio OR (rate AND pattern)` -- which build_system keeps as
        an alternative.

        Args:
            threshold (int): weighted-spike total at which the alarm fires (default policy: 2).

        Returns:
            list[str]: single white-hole threshold rule for the Decision neuron.
        """
        spikes = "^{" + str(threshold) + ",}" if threshold > 1 else ""
        return [f"a{spikes}/a+\\to a;0"]
