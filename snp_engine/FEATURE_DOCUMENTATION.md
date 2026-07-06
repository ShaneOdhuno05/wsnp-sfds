# Feature Documentation: The SN P Engine and the Detector Built on It

This document explains, from first principles, how the detector actually *computes*. The
[top-level README](../README.md) tells you what the detector does and how to run it; the
[`traffic_generation`](../traffic_generation/FEATURE_DOCUMENTATION.md) and
[`packet_encoding`](../packet_encoding/FEATURE_DOCUMENTATION.md) companions explain how raw
traffic becomes a stream of symbols. This one picks up where they leave off: how those symbols
drive a Spiking Neural P system, and how that system decides whether a window looks like a SYN
flood. By the end you should be able to rebuild the engine and the detector yourself.

The code lives in `snp_engine/` (the engine) and, one directory up, in `per_source_builder.py`
and `rulemaker.py` (which assemble the detector). We will build up to those.

---

## Part 1 — Spiking Neural P systems in one page

A **Spiking Neural P (SN P) system** is a small, biologically-inspired model of computation. It
is a directed graph of **neurons** joined by **synapses**. Each neuron holds a whole number of
identical **spikes**, and computation proceeds in discrete **ticks**. On every tick a neuron
may apply a **rule**: it consumes some of its spikes and produces new ones, which travel along
its outgoing synapses to other neurons. The system **halts** when no neuron has anything left
to do.

Two details make our variant expressive enough to be useful:

- **Weighted synapses.** A synapse carries a weight, and a spike crossing it is multiplied by
  that weight. Crucially, weights may be **negative** — a neuron can *subtract* spikes from a
  downstream neuron. This is the "weighted" in *weighted SN P system*, and it is what lets us do
  the arithmetic the ratio feature needs.
- **Firing rules with thresholds.** A rule has a *guard* — a condition on how many spikes the
  neuron currently holds — and fires only when the guard matches. A rule that fires on "this
  many or more" spikes is exactly a threshold detector.

That is the whole model. Everything below is an application of it.

---

## Part 2 — The engine (`snp_engine/`)

The engine runs an SN P system and records what happens. It is exposed as a small FastAPI
service so the experiment driver can hand it a system as JSON and get back a tick-by-tick
history. Four files matter:

- **`schema.py`** defines the wire format with Pydantic: a system is a list of `neurons` and a
  list of `synapses`, where a synapse is a `(source, target, weight)` triple.
- **`neuron.py`** defines the three kinds of neuron.
- **`rule.py`** parses and evaluates a single firing rule.
- **`system.py`** drives the whole network tick by tick and snapshots it.

### The three neuron types

Every neuron communicates the same way: upstream neurons drop spikes into its mailbox with
`receive()`, and those spikes are folded in at the start of its next `activate()`. The three
types differ only in what `activate()` does.

- **`Input`** replays a fixed spike train — the encoded packet window — one symbol per tick. It
  only ever sends. When it emits the symbol `3`, it sends $3$ spikes along each outgoing synapse
  (the symbol's numeric value *is* the spike count, which matters in a moment).
- **`Regular`** is the workhorse. It stores a spike count, checks its rules against that count,
  and if one fires, consumes the spikes it eats and sends its products downstream. Every detector
  neuron is a `Regular`.
- **`Output`** is a sink. It accumulates whatever it receives and records the running total; it
  never sends onward.

### How a tick executes

`SNPSystem.simulate()` repeats one step until the system halts; each step calls `activate()` on
every neuron and records a snapshot. The core of a `Regular` neuron's `activate()` shows the
weighted-synapse mechanism directly — note that the produced spikes are multiplied by each
target's synapse weight on the way out:

```python
fireable = self._fireable_rules()      # rules whose guard matches the current spike count
self._spikes += self._incoming         # fold in spikes that arrived this tick
self._incoming = 0
if not fireable:
    return                             # nothing to do this tick

rule, (consumed, produced, delay) = random.choice(fireable)
self._consume(consumed)                # eat the spikes this rule consumes
for weight, target in self.target:
    target.receive(weight * produced)  # send the product onward, scaled by the synapse weight
```

A neuron reports itself "still active" — so the system has not halted — while it has spikes
arriving, spikes stored, or any applicable rule. (The model also supports delayed spikes; the
detector never uses them, and `neuron.py` documents that dormant path honestly rather than
pretending it is exercised.)

### The anatomy of a rule

A rule is written `guard / consumed -> produced ; delay`. `rule.py` parses this into a guard
regex (over a string of `a`s) plus the integer effects. The two forms we use are:

- `a^{k}/a^{k} -> a; 0` — "when holding **exactly** $k$ spikes, consume $k$ and emit one, now."
  This is how a counter recognises a specific symbol.
- `a^{k,}/a+ -> a; 0` — "when holding $k$ **or more**, consume them all and emit one." The `{k,}`
  makes this a **threshold**; the `a+` ("white-hole", consume-all) clears the neuron. This is how
  a detector fires.

---

## Part 3 — From packets to spikes (a one-paragraph recap)

The encoder (see the [`packet_encoding` doc](../packet_encoding/FEATURE_DOCUMENTATION.md)) turns
each attacker packet into one symbol — `1` other, `2` anomalous/bogon SYN, `3` normal SYN, `4`
ACK — and ends each `(window, device)` substream with a `5`. The key idea to carry into the next
part is that **a symbol's value is the number of spikes it injects**, so a symbol can be made to
trigger exactly one counter neuron.

---

## Part 4 — Building the detector (`per_source_builder.py`, `rulemaker.py`)

`build_system(n, base, ratio, rate_K, pattern_P, H, ...)` assembles the network for `n` parallel
sources (the trailing arguments set the vote weights and threshold, covered below). `rulemaker.py`
generates the individual rules; `per_source_builder.py` wires the neurons and synapses together.
The shape is one **chain per source** feeding a small set of **detectors**, which in turn feed a
short **voting layer**.

### One chain per source

For each source *i*, an `Input` neuron `Packets_i` replays that source's symbol stream and fans
out to four counter neurons, each built with `make_symbol_rules`:

| Counter | Fires on symbol | Meaning |
| ------- | --------------- | ------- |
| `AnomalousSYN_i(2)`   | `2` | a bogon (spoofed-range) SYN |
| `NormalSYN_i(3)`      | `3` | an ordinary SYN |
| `NormalACK_i(4)`      | `4` | a completed handshake's ACK |
| `StreamEndDetector_i` | `5` | the end-of-substream marker |

`make_symbol_rules` is what specialises a counter to its symbol — one rule that fires on exactly
that symbol, plus a forgetting rule (`-> \lambda`, produce nothing) for every other symbol:

```python
def make_symbol_rules(self, symbol: int) -> list[str]:
    rules = [f"a^{{{symbol}}}/a^{{{symbol}}}\\to a;0"]                                       # spike on this symbol
    rules += [f"a^{{{s}}}/a^{{{s}}}\\to\\lambda" for s in (1, 2, 3, 4, 5) if s != symbol]   # forget the rest
    return rules
```

So `NormalSYN_i(3)` is built with `make_symbol_rules(3)`. When `Packets_i` emits symbol `3`
(three spikes), only this counter matches its `a^{3}` guard and emits a single spike; the other
counters receive three spikes, match their *forgetting* rule, and discard them. In effect, **each
counter emits exactly one spike every time its symbol appears**, and ignores everything else.
Symbol `1` ("other") injects a single spike that every counter forgets — it is deliberately
inert. Those single spikes are what the detectors count.

### The three features

The detector reports three features, each a neuron (or group) that counts its inputs and fires
on a threshold. Two are **aggregate** — they sum over all sources — and one is **per-source**.

- **Rate** (`RateDetector`, aggregate). Every `AnomalousSYN_i` and `NormalSYN_i` sends one spike
  per SYN into a single shared `RateDetector`, whose rule `a^{rate_K,}/a+ -> a; 0` fires once the
  total SYN count in the window reaches `rate_K`. This is a *velocity*: how many connection
  attempts arrived, regardless of who sent them.
- **Pattern** (`PatternDetector`, aggregate). Every `AnomalousSYN_i` *also* sends one spike into a
  shared `PatternDetector`, which fires at `pattern_P` bogon SYNs. This measures the volume of
  spoofed, reserved-range source addresses.
- **Ratio** (`RatioDetector_i -> RatioOR`, per-source). Each source gets its *own* `RatioDetector_i`
  that tests whether that source's SYN-to-ACK proportion is lopsided. Their outputs feed a single
  `RatioOR` neuron (rule `a+ -> a; 0`), so the ratio feature fires if **any one** source looks
  half-open. Part 5 explains how a neuron tests a ratio using only spike counts.

Those three detectors are the system's independent *views* of the window. `analyzer.py` reads each
one's firing straight from the history — but the detectors also feed a small voting layer that
distils them into a single alarm.

### The alarm: a 2-of-3 majority vote

Alongside the three feature verdicts, the detector emits one combined alarm. The default policy is a
**flat 2-of-3 majority**: raise the alarm when at least two of the three features agree, and never on
one alone. (Why require corroboration? A lone ratio trip especially is ambiguous at low volume — a
legitimate client retrying a dead service, or a handshake whose ACK lands in the next window, looks
identical to a stealthy half-open source — so a single feature is treated as a *view*, not a verdict.)

There is one snag in building this from spiking neurons. A detector's rule is a white-hole (`a^{k,}/a+`):
on a busy window it crosses its threshold, consumes everything, refills, and fires *again* —
`PatternDetector` can fire a dozen times in one window. A vote that simply counted spikes would read
those repeats as many separate features and trip on a single loud one. So each feature is first passed
through a one-shot **flag** that collapses any number of firings into a single spike. The flag starts
pre-loaded with 2 spikes:

```python
def make_flag_rules(self) -> list[str]:
    return ["a^{3}/a^{3}\\to a;0",          # first firing: 2 + 1 = 3 -> emit one spike, reset to 0
            "a^{1}/a^{1}\\to\\lambda"]       # every later firing: 0 + 1 = 1 -> forget it, no output
```

The first detector firing lifts the flag 2→3, so the exact-match rule fires once and emits a single
spike; any later firing only reaches 1, which the forget rule discards. (This is the gate trick from the
original SFDS.) `Decision` then votes over the three clean flags — by default with equal weights:

```python
{"from": "RatioFlag",   "to": "Decision", "weight": ratio_weight},     # 1
{"from": "RateFlag",    "to": "Decision", "weight": rate_weight},      # 1
{"from": "PatternFlag", "to": "Decision", "weight": pattern_weight},   # 1
```

and the rule `a^{2,}/a+ -> a; 0` (from `make_decision_rule`): fire once two spikes accumulate. With equal
weights that is exactly "any two features," i.e. 2-of-3 majority. `Decision -> Output`, and `analyzer.py`
reads its firing as the window's `alarm`.

The weights are parameters of `build_system`. Setting `ratio_weight` to 2 turns the same machinery into a
**ratio-anchored** vote — ratio (2) then clears the threshold by itself, giving `ratio OR (rate AND
pattern)`. It is kept as a documented alternative, but the default is the flat majority: ratio-anchored
trades freedom from those low-volume false positives for the ability to catch a lone stealthy source, and
which way to lean is exactly what the threshold sweep is meant to settle.

---

## Part 5 — Testing a ratio with only spike counts

The ratio feature wants to fire when a source's proportion of unanswered SYNs is too high —
formally, when $S / (S + A) > R$, where $S$ is that source's SYN count, $A$ its ACK count, and
$R$ the threshold (say $0.70$). A neuron cannot divide. But it can add and subtract whole spikes,
and that turns out to be enough.

Start from the inequality and clear the fraction (valid because $S + A > 0$):

$$\frac{S}{S + A} > R \quad\Longleftrightarrow\quad S > R\,(S + A)$$

Write the threshold as a ratio of whole numbers, $R = \text{ratio}/\text{base}$ (for $R = 0.70$,
take $\text{ratio} = 70$ and $\text{base} = 100$). Multiplying through by $\text{base}$ gives an
all-integer test:

$$\text{base}\cdot S \;>\; \text{ratio}\cdot(S + A) \quad\Longleftrightarrow\quad (\text{base} - \text{ratio})\cdot S \;-\; \text{ratio}\cdot A \;>\; 0$$

Now it is just addition and subtraction, which weighted synapses do directly. `build_system`
turns the two coefficients into synapse weights, plus two offsets keyed to $H$ — the most packets
a single source can contribute to one window:

```python
syn_w    = base - ratio         # +(base - ratio) spikes per SYN
ack_w    = -ratio               # -ratio spikes per ACK
init     = ratio * H            # starting offset, so the running count never goes negative
finalize = (base - ratio) * H   # added once, by StreamEndDetector_i, at end of stream
```

and wires them straight into `RatioDetector_i`:

```python
{"from": f"AnomalousSYN_{i}(2)",   "to": f"RatioDetector_{i}", "weight": syn_w},
{"from": f"NormalSYN_{i}(3)",      "to": f"RatioDetector_{i}", "weight": syn_w},
{"from": f"NormalACK_{i}(4)",      "to": f"RatioDetector_{i}", "weight": ack_w},
{"from": f"StreamEndDetector_{i}", "to": f"RatioDetector_{i}", "weight": finalize},
```

Two practical wrinkles are handled by those offsets:

1. **Spike counts can never go negative** (the engine enforces it). A window that starts with
   ACKs would drive the running total below zero. The offset $\text{init} = \text{ratio}\cdot H$
   is larger than the most any window of ACKs could subtract, so the total stays non-negative.
2. **The verdict must wait for the whole window.** With the offset, the running total mid-window
   peaks at $\text{base}\cdot H$ (all SYNs, no ACKs), so the firing threshold is set just above
   that, at $\text{base}\cdot H + 1$. Nothing can reach it during the stream. Only when the `5`
   marker arrives does `StreamEndDetector_i` add the final $(\text{base} - \text{ratio})\cdot H$,
   lifting the total to

   $$\text{base}\cdot H \;+\; (\text{base} - \text{ratio})\cdot S \;-\; \text{ratio}\cdot A$$

   which clears $\text{base}\cdot H + 1$ exactly when $(\text{base} - \text{ratio})\cdot S - \text{ratio}\cdot A > 0$
   — that is, exactly when $S/(S + A) > R$.

That threshold, $\text{base}\cdot H + 1$, is generated by `make_proportion_detector_rules`; the
strict `+ 1` is the load-bearing detail that makes it a strict inequality:

```python
def make_proportion_detector_rules(self, hard_limit: int, base: int) -> list[str]:
    total = hard_limit * self._n_inputs
    threshold = (base * total) + 1          # base*H + 1: just above the mid-window ceiling
    t = "{" + str(threshold) + ",}" if threshold > 1 else ""
    return [f"a{t}/a+\\to a;0"]              # fire on `threshold` or more spikes, then consume all
```

So a neuron that can only count has been made to evaluate a proportion, deferred cleanly to the
end of the window. That is the heart of the contribution.

---

## Part 6 — Why ratio is per-source but rate and pattern are aggregate

A distributed flood is defined by its *totals*, so summing rate and pattern over all sources is
exactly the right signal: ten sources sending a little each still add up to a flood. Summing is
also **partition-invariant** — the total is the same however you slice the traffic among sources
— so making rate or pattern per-source would change nothing.

Ratio is different, and this is what makes "multiple sources" matter rather than being window
dressing. Imagine one source quietly holding connections half-open while several well-behaved
sources complete theirs. In the *aggregate*, the polite ACKs drown out the one bad source's
missing ACKs, and the proportion looks fine. Give each source its **own** `RatioDetector_i` and
OR the results, and that single stealthy source lights up on its own chain instead of being
averaged away. The parallelism is not decoration; it is what lets the detector see a culprit a
single lumped view would hide. (Grouping is by sending **device**, not source IP, because a flood
can forge its IP but not its layer-2 MAC.)

---

## Part 7 — A window's journey, end to end

Putting it together, here is what happens to one window of one source whose encoded stream is
`3 4 3 2 5` — two normal SYNs, one completed ACK, one bogon SYN, then the end marker:

1. `Packets_i` replays the symbols one per tick. Each injects its value in spikes, so the matching
   counter (`NormalSYN_i`, `NormalACK_i`, `AnomalousSYN_i`, …) emits a single spike; the others forget.
2. Those spikes flow to the detectors. `RateDetector` and `PatternDetector` accumulate aggregate
   totals across all sources; `RatioDetector_i` accumulates $(\text{base} - \text{ratio})$ per SYN
   and $-\text{ratio}$ per ACK, on top of its $\text{ratio}\cdot H$ offset.
3. The `5` makes `StreamEndDetector_i` finalise the ratio neuron. Any detector that crossed its
   threshold has fired, and its one-shot flag passes a single spike to `Decision`; once two flags
   have spiked, `Decision` fires and spikes `Output` — the alarm.
4. `system.py` has recorded which rule each neuron fired on every tick. `simulator.py` writes that
   history to CSV, and `analyzer.py` scans it: a fired `RateDetector` / `RatioOR` / `PatternDetector`
   becomes a `T` in the window's `(rate, ratio, pattern)` verdict, and a fired `Decision` is the
   combined `alarm`.

That verdict, compared against the capture's known label, is what the evaluation in the README
checks — eight scenarios, each landing on its expected combination of the three features (and the
expected alarm).
