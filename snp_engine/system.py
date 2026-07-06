"""Executes a Spiking Neural P system: the simulation engine behind the FastAPI service.

``SNPSystem`` takes a parsed system description (neurons plus weighted synapses, validated
by ``schema.py``), builds the runtime neurons from ``neuron.py``, and runs the network one
tick at a time until it halts. After every tick it records a snapshot of each neuron — the
``_history`` that ``main.py`` returns to the caller and that the analysis tooling reads.
"""

from snp_engine.neuron import Input, Output, Regular, Neuron
from logger import Log, Style
import snp_engine.schema as schema


class SNPSystem:
    """A runnable SN P system: its neurons, their synapses, and the per-tick history."""

    def __init__(self, system: schema.SNPSystem) -> None:
        self._tick = -1
        self._neurons: dict[str, Neuron] = {
            neuron.id: neuron for neuron in map(SNPSystem._parse_neuron, system.neurons)
        }
        self._parse_synapse(system.synapses)
        self._expected: list[schema.Data] = (
            system.expected if system.expected is not None else []
        )
        self._history: list[dict[str, Neuron]] = []
        self._make_history()
        Log.debug(self)
        self.simulate_step()

    def __repr__(self) -> str:
        indent = " " * 10
        neurons = f"\n{indent}".join(
            f"{i + 1}: {neuron}" for i, neuron in enumerate(self._neurons.values())
        )
        return f"Expected: {self._expected}\n{indent}Neurons: {len(self._neurons)}\n{indent}{neurons}"

    def simulate(self) -> None:
        """Run ticks until no neuron has any work left."""
        while not self._check_if_halted():
            self.simulate_step()

    def simulate_step(self, is_tick: bool = True) -> None:
        """Advance the whole network by one tick: fire every neuron, then snapshot the state.

        ``is_tick`` lets the step API take a snapshot without advancing the tick counter; a
        normal run always advances.
        """
        Log.info(Style.GREEN + Style.UNDERLINE + f"TICK: [{self._tick}]" + Style.ENDC)
        for neuron in self._neurons.values():
            neuron.activate()
        if is_tick:
            self._tick += 1
        self._make_history()
        Log.debug(self)

    def _check_if_halted(self) -> bool:
        """Report whether the system has halted — true once every neuron is inactive."""
        Log.info("Checking for active neurons...")
        for neuron in self._neurons.values():
            if neuron.is_active():
                Log.info(f'Neuron "{neuron.id}" is still active')
                return False
        Log.info("No more active neurons. Finishing simulation.")
        return True

    def _make_history(self) -> None:
        """Append a snapshot of every neuron to ``_history``.

        For a regular neuron the snapshot records which rule it just fired; for an input or
        output neuron it records the neuron's current spike string.
        """
        snapshot: dict[str, Neuron] = {}
        for key, neuron in self._neurons.items():
            if isinstance(neuron, Regular):
                fired = neuron._activated_rule._raw if neuron._activated_rule else ""
                snapshot[key] = {
                    "type": neuron._type,
                    "rule": fired,
                    "data": neuron._spikes,
                }
            else:
                snapshot[key] = {"type": neuron._type, "data": neuron._data}
        self._history.append(snapshot)

    def _parse_synapse(self, synapses: list[schema.Synapse]) -> None:
        """Attach each synapse to its source neuron as a ``(weight, target)`` pair.

        An output neuron may only receive, never send, so a synapse leaving one is rejected.
        """
        for synapse in synapses:
            source = self._neurons[synapse.source]
            target = self._neurons[synapse.target]
            if isinstance(source, Output):
                Log.error("Invalid synapse: ", synapse)
                raise SyntaxError(f"Invalid synapse: {synapse}")
            if isinstance(target, (Regular, Output)):
                source.target.append((synapse.weight, target))

    @classmethod
    def _parse_neuron(cls, neuron: schema.Neuron) -> Neuron:
        """Build the runtime neuron (``Input`` / ``Output`` / ``Regular``) for one schema entry.

        The schema already constrains the shapes below, so anything that falls through is an
        impossible state and is treated as a hard error.
        """
        match (type(neuron), neuron.type):
            case (schema.IO, "input") if type(neuron.data) is str:
                return Input(neuron.id, neuron.data)
            case (schema.IO, "output") if type(neuron.data) is str:
                return Output(neuron.id, neuron.data)
            case (schema.Regular, "regular") if type(neuron.data) is int:
                return Regular(neuron.id, neuron.data, neuron.rules)
        Log.fatal("Invalid or impossible neuron specification: ", type(neuron))
        raise TypeError(f"Invalid or impossible neuron specification: {type(neuron)}")
