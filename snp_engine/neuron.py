"""The three neuron types that make up a Spiking Neural P (SN P) system.

An SN P system is a directed graph of neurons joined by weighted synapses. Each neuron
holds some number of identical spikes, and on every tick it may fire a rule: consume
some of its stored spikes and send freshly produced spikes along its outgoing synapses,
scaled by each synapse's weight. The engine in ``system.py`` drives the computation —
once per tick it calls ``activate()`` on every neuron, and it uses ``is_active()`` to
decide when the system has halted.

Three kinds of neuron implement that contract:

  * ``Input``   — replays a fixed spike train (an encoded packet window), one symbol per
                  tick, into its targets. It produces spikes but never consumes them.
  * ``Regular`` — the workhorse: it stores a spike count, applies firing rules (parsed by
                  ``rule.py``), and forwards produced spikes downstream. Every detector
                  neuron — the per-symbol counters, ``RateDetector``, ``RatioDetector_i``,
                  ``PatternDetector`` and ``RatioOR`` — is a ``Regular``.
  * ``Output``  — a sink: it accumulates whatever it receives and records the running
                  total, and never sends anything onward.

Neurons never call one another directly. They communicate only by depositing spikes in a
target's mailbox through ``receive()``, and those spikes are folded in on the target's
next ``activate()``.
"""

from __future__ import annotations
import random
from itertools import groupby
from typing import Literal, Union
from logger import Log, Style
from snp_engine.rule import Rule

# A synapse as seen from its source neuron: (weight, target neuron).
type Target = tuple[int, Regular | Output]
type Neuron = Union[Input, Output, Regular]
type NeuronTypes = Literal["input", "regular", "output"]


def _render_spikes(spikes: str) -> str:
    """Run-length encode a raw spike string for display and history.

    For example ``"aaab"`` becomes ``"a^{3}b"``: a run longer than one is written as
    ``symbol^{count}``, and a run of one is left as the bare symbol.
    """
    return "".join(
        f"{symbol}^{{{count}}}" if (count := len(list(group))) > 1 else symbol
        for symbol, group in groupby(spikes)
    )


class Input:
    """Replays a fixed spike train, one symbol per tick, into its targets.

    ``_remaining`` holds the spikes still to be sent (for example ``"532"``); ``_data`` is
    the same content in run-length display form and is what the engine records in its
    history. An input neuron only ever sends — it never receives or consumes.
    """

    def __init__(self, id: str, data: str | None) -> None:
        self.id = id
        self._type: NeuronTypes = "input"
        self._remaining: str = data if data else ""
        self.target: list[Target] = []
        self._data: str = _render_spikes(self._remaining)

    def __repr__(self) -> str:
        targets = ", ".join(f"{weight}->{target.id}" for weight, target in self.target)
        return f'Input {self.id}: "{self._data}"; targets: {targets or "none"}'

    def is_active(self) -> bool:
        """Report whether any spikes remain to be replayed."""
        return bool(self._remaining)

    def activate(self) -> None:
        """Send the next spike in the train to every target (weight × the spike's value)."""
        if not self._remaining:
            return
        spike = self._remaining[0]
        self._remaining = self._remaining[1:]
        self._data = _render_spikes(self._remaining)
        Log.info(
            f"{self.id}: {Style.RED + spike + Style.ENDC + self._data} -> {self._data}"
        )
        for weight, target in self.target:
            target.receive(weight * int(spike))


class Output:
    """A sink neuron: it accumulates received spikes and records the running total each tick.

    ``_incoming`` is the number of spikes received since the last tick; on ``activate()``
    that total is appended to ``_remaining`` and reflected in ``_data`` (the display and
    history form). An output neuron only ever receives — it never sends.
    """

    def __init__(self, id: str, data: str | None) -> None:
        self.id = id
        self._type: NeuronTypes = "output"
        self._remaining: str = data if data else ""
        self._incoming: int = 0
        self._data: str = _render_spikes(self._remaining)

    def __repr__(self) -> str:
        return f'Output {self.id}: "{self._data}"'

    def is_active(self) -> bool:
        """Report whether spikes are waiting to be recorded."""
        return self._incoming > 0

    def receive(self, spikes: int) -> None:
        """Accept spikes from an upstream neuron; they are recorded on the next ``activate()``."""
        self._incoming += spikes

    def activate(self) -> None:
        """Append this tick's received total to the recorded train."""
        Log.info(
            f"{self.id}: {self._data} -> {self._data + Style.GREEN + str(self._incoming) + Style.ENDC}"
        )
        self._remaining += str(self._incoming)
        self._incoming = 0
        self._data = _render_spikes(self._remaining)


class Regular:
    """A spiking neuron: it stores spikes, fires rules, and forwards spikes to its targets.

    State it carries between ticks:
      * ``_spikes``   — the spikes currently stored in the neuron.
      * ``_incoming`` — spikes received during the current tick, folded into ``_spikes`` at
                        the start of the next ``activate()``.
      * ``_delayed``  — a map from a remaining delay (in ticks) to the spikes scheduled to
                        be released that many ticks from now.

    Firing follows standard SN P semantics. A rule whose guard matches the current spike
    count is *applicable*; if several are applicable, one is chosen at random. (This
    detector is constructed so that at most one rule is ever applicable per neuron, which
    is exactly what makes a run reproducible.) The chosen rule consumes some spikes and
    produces others, and each produced spike is sent to every target scaled by the
    synapse weight.

    A note on delays: a rule written ``… -> a; d`` with ``d > 0`` is meant to hold its
    output for ``d`` ticks before releasing it. This detector uses only ``; 0`` (no-delay)
    rules, so ``_delayed`` stays ``{0: 0}`` and the delayed path is never exercised. Be
    aware that the per-tick countdown which would advance those buckets is not currently
    implemented, so a non-zero delay would never actually release. That is a latent
    limitation rather than an active bug here; it is documented and left as-is so this
    refactor changes no observable behaviour.
    """

    def __init__(self, id: str, data: int | None, rules: list[str]) -> None:
        self.id = id
        self._type: NeuronTypes = "regular"
        self.target: list[Target] = []
        self._spikes: int = data if data else 0
        self._incoming: int = 0
        self._delayed: dict[int, int] = {0: 0}
        self._rules: list[Rule] = [Rule.parse_rule(rule) for rule in rules]
        self._activated_rule: Rule | None = None

    def __repr__(self) -> str:
        fired = f" [fired {self._activated_rule._raw}]" if self._activated_rule else ""
        targets = ", ".join(f"{weight}->{target.id}" for weight, target in self.target)
        return (
            f"Regular {self.id}: {self._spikes} spike(s), {len(self._rules)} rule(s)"
            f"{fired}; targets: {targets or 'none'}"
        )

    def receive(self, spikes: int) -> None:
        """Accept spikes from an upstream neuron; folded into the stored count on ``activate()``."""
        self._incoming += spikes

    def is_active(self) -> bool:
        """Report whether the neuron still has work: spikes arriving, spikes scheduled, or a fireable rule."""
        return (
            self._incoming > 0
            or self._delayed[0] > 0
            or len(self._delayed) > 1
            or bool(self._fireable_rules())
        )

    def activate(self) -> None:
        """Advance one tick: absorb arriving spikes, then — if a rule fires — consume and emit."""
        fireable = self._fireable_rules()
        self._spikes += self._incoming
        self._incoming = 0

        if not fireable:
            self._activated_rule = None
            self._validate_neuron()
            return

        rule, (consumed, produced, delay) = random.choice(fireable)
        self._activated_rule = rule
        Log.info(f"{self.id}: {Style.GREEN + rule._raw}")
        self._consume(consumed)

        ready_now = self._delayed[
            0
        ]  # spikes whose delay has elapsed (always 0 here — see class docstring)
        for weight, target in self.target:
            if delay == 0:
                target.receive(weight * (ready_now + produced))
            else:
                self._delayed[delay] = self._delayed.get(delay, 0) + produced
                target.receive(weight * ready_now)
        self._validate_neuron()

    def _fireable_rules(self) -> list[tuple[Rule, tuple[int, int, int]]]:
        """Return the rules that are applicable at the current spike count.

        Each entry pairs the rule with its ``(consumed, produced, delay)`` outcome, as
        computed by ``Rule.activate``. A rule that does not match contributes nothing.
        """
        fireable = []
        for rule in self._rules:
            outcome = rule.activate(self._spikes)
            if outcome is not None:
                fireable.append((rule, outcome))
        return fireable

    def _consume(self, count: int) -> None:
        """Remove ``count`` spikes from the stored total, logging the before and after."""
        before = self._spikes
        self._spikes -= count
        color = Style.RED if before > self._spikes else Style.GREEN
        Log.info(f"{self.id}: {before} -> {color}{self._spikes}{Style.ENDC}")

    def _validate_neuron(self) -> None:
        """Enforce the invariant that a neuron can never hold a negative number of spikes."""
        if self._spikes < 0:
            Log.error("Invalid state! Negative spike found in neuron: ", self.id)
            raise RuntimeError(
                "Invalid state! Negative spike found in neuron: ", self.id
            )
