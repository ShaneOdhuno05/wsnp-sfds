# Distributed SYN-Flood Detection with a Weighted Spiking Neural P System

This is a research codebase for detecting TCP SYN-flood attacks with a **weighted Spiking Neural P (SN P) system**.
It contains both the detector and the full data pipeline that feeds it: a local multi-source traffic lab,
a windowing/encoding stage, the SN P simulation engine, and the experiment drivers used to evaluate it.

The detector treats a flood as a *distributed* phenomenon: traffic arrives from several sources in parallel,
and the SN P system processes each source on its own neuron chain — the parallelism that membrane computing
is built for.

---

## What it detects

The detector reports three independent features for each time window. Each is a separate neuron (or group of
neurons) in the SN P system, so a window can trigger any subset of them.

| Feature     | Neuron(s)                       | What it measures                                                                 | Scope                  |
| ----------- | ------------------------------- | -------------------------------------------------------------------------------- | ---------------------- |
| **Rate**    | `RateDetector`                  | **Velocity** — total SYNs per window across all sources reaches a threshold `K`. | Aggregate              |
| **Ratio**   | `RatioDetector_i` → `RatioOR`   | **SYN:ACK proportion** `S/(S+A)` for *one* source exceeds a threshold `R`.        | **Per-source**         |
| **Pattern** | `PatternDetector`               | **Bogon volume** — SYNs from reserved/test-net (spoofed) ranges reach `P`.        | Aggregate              |

`Rate` and `Pattern` are **aggregate**: a distributed flood is defined by its *total* volume, and summing over
sources is the right signal. `Ratio` is **per-source** and OR'd across sources (`RatioOR`): it fires if *any*
single source is disproportionately half-open. This is what makes multiple sources matter — one stealthy
half-open source is isolated on its own chain instead of being diluted into a calm-looking aggregate.

The three features stay **independent views** — the system exposes each one rather than only a final verdict.
On top of them sits a single alarm: a `Decision` neuron takes a **flat 2-of-3 majority** vote and fires when at
least two of the three features agree:

$$\text{alarm} = \big[ \text{rate} + \text{ratio} + \text{pattern} \ge 2 \big].$$

No single feature raises the alarm alone — a lone ratio trip is ambiguous at low volume (a client retrying a
dead service, or a handshake whose ACK lands in the next window, looks the same as a stealthy half-open source).
An engineer can still read the three feature neurons to see *why* the alarm fired. (Each detector is a white-hole
rule that may fire several times in a busy window, so the vote reads each feature through a one-shot `*Flag`
neuron that collapses any number of firings into a single spike — see [`rulemaker.py`](rulemaker.py).) Setting
`ratio_weight` to 2 in `build_system` turns the same machinery into a **ratio-anchored** vote, where ratio
alarms on its own (`ratio OR (rate AND pattern)`); it is kept as a documented alternative. The weights are
provisional, pending the threshold sweep.

---

## How it fits together

The pipeline runs in four stages, each feeding the next:

- **`traffic_generation/`** (Linux netns) puts *N* attacker namespaces and one victim on a single L2 bridge. Each
  attacker is a distinct device (a fixed source MAC), so the capture can attribute every packet to its source even
  under IP spoofing. It produces a capture (CSV + PCAP) recording each packet's flags, addresses, and source MAC (the
  `device` column).
- **`packet_encoding/`** splits that capture into fixed-Δt windows and encodes each `(window, device)` substream into
  the SN P symbol alphabet — one encoded line per `(window, device)`.
- **`simulator.py`** builds the per-source SN P system in memory via `per_source_builder`, feeds source *i* to input
  neuron *i*, and POSTs each window to the running engine (`snp_engine`, a FastAPI service) at `/simulate`, getting
  per-tick neuron states back. It writes the per-window firings to `decision_history_*.csv`.
- **`analyzer.py`** reads those firings, compares them to the expected label, and writes `output-decision_history.json`.

`analysis/inspect_capture.py` is an **independent oracle**: it computes the expected `(rate, ratio, pattern)`
label straight from a capture CSV, so the SN P detector's output can be checked against ground truth.

---

## Directory structure

- **`simulator.py`** — per-capture driver: preprocess → encode → simulate → score.
- **`n_simulator.py`** — threshold sweep over many captures (RQ3); emits `results_*.csv` (plus plots).
- **`per_source_builder.py`** — builds the *n*-source SN P system (neurons + synapses) in memory.
- **`rulemaker.py`** — generates the spiking rules for each neuron type.
- **`analyzer.py`** — scores decision histories against expected labels.
- **`logger.py`** — the shared logger.
- **`SFDS-v3-multisource.json`** — the per-source detector exported in Websnapse visual-simulator format.
- **`snp_engine/`** — the FastAPI service that executes an SN P system: `main.py` serves `POST /simulate`, with
  `system.py`, `neuron.py`, `rule.py`, and `schema.py`.
- **`packet_encoding/`** — Stage 2–3: `data_preprocessor.py` (fixed-Δt windowing of a capture) and `packet_encoder.py`
  (per-`(window, device)` symbol encoding).
- **`traffic_generation/`** — Stage 1, the multi-source lab: `setup_netns.sh` (creates the victim + *N* attacker
  namespaces), `scenario_runner.py` (orchestrates a scenario), `scenarios.json` (the 8 labeled scenarios),
  `attacker/traffic_generator.py`, `victim/tcp_server.py`, `victim/packet_capture.py`, and `experiments/` (where
  captures land — the 8 reference captures live here).
- **`analysis/inspect_capture.py`** — the ground-truth oracle: predicts `(rate, ratio, pattern)` straight from a capture.
- **`sweep_results/`** — saved threshold-sweep outputs.
- **`requirements.txt`**, **`.gitignore`**, and this **`README.md`**.

---

## Requirements

- **Python ≥ 3.12** (the code uses nested same-quote f-strings).
- Install dependencies:

  ```bash
  pip install -r requirements.txt
  ```

  (`fastapi`, `uvicorn`, `pydantic`, `requests`, `matplotlib`, `scapy`.)

- **Generating fresh traffic** (Stage 1) uses Linux **network namespaces** and requires a Linux host with `sudo`
  (`ip netns`, a bridge, `veth` pairs). Everything downstream — encoding, the SN P engine, the drivers, and the
  oracle — is cross-platform and runs against the included reference captures without the lab.

All commands below are run **from the repository root** (the modules import each other by top-level name,
and `snp_engine` must be importable as a package).

---

## Running the detector

You can reproduce the evaluation with the included captures — no traffic lab needed.

**The quick way:** start the engine (step 1 below), then run `python verify.py` from this directory. It runs all
eight reference scenarios and prints a pass/fail table, exiting non-zero if any verdict is wrong (so it doubles as a
smoke test). The steps that follow show how to run a single capture by hand.

### 1. Start the SN P engine

On your terminal:

```bash
uvicorn snp_engine.main:app --port 8000
```

This serves `POST /simulate` on `http://localhost:8000` (the default `simulator.py` expects). Leave it running.

### 2. Run a capture through the detector

In another terminal (still at the repository root):

```bash
python simulator.py per-source \
  --file-path traffic_generation/experiments/normal_2026-06-26_150337.csv \
  --input-sources 3 \
  --expected-result FFF \
  --export-dir-path normal_2026-06-26_150337
```

`simulator.py` preprocesses the capture into windows, encodes it, builds a 3-source SN P system, POSTs each
window to the engine, then scores the result. Outputs (windowed CSVs, the encoded text, per-window
`decision_history_*.csv`, and `output-decision_history.json`) are written into the `--export-dir-path` directory
and are git-ignored.

Notes on the arguments:

- **`--input-sources`** must equal the number of attacker **devices** in the capture. The reference captures have
  **3** devices.
- **`--expected-result`** is the ground-truth label as a 3-char `rate,ratio,pattern` string of `T`/`F` (e.g.
  `TTF`). It is only used for scoring, not detection — see the table below.
- **`--export-dir-path`** should end in a directory **named after the capture file** (without `.csv`). The encoder
  derives window filenames from that name, so they must match. Use a single-level name (its parent is the repository root).
- The positional `SYSTEM` argument (`per-source` above) is retained for backward compatibility and **ignored** at
  runtime — the system is built in memory by `per_source_builder`. Pass any placeholder.

### 3. Cross-check against the oracle

Afterwards, you can also then run:

```bash
python analysis/inspect_capture.py traffic_generation/experiments/normal_2026-06-26_150337.csv
```

This prints the expected `(rate, ratio, pattern)` label computed directly from the capture (peak SYN/window for
rate, max per-device `S/(S+A)` for ratio, peak bogon SYN/window for pattern). The detector's firings should agree.

---

## Scenarios and expected labels

`traffic_generation/scenarios.json` defines eight labeled scenarios; the eight reference captures in
`traffic_generation/experiments/` are one run of each. Labels are `(rate, ratio, pattern)`:

| Scenario        | Capture prefix    | Label | What it exercises                                                          |
| --------------- | ----------------- | ----- | -------------------------------------------------------------------------- |
| `normal`        | `normal_…`        | `FFF` | Three well-behaved sources; everything calm.                               |
| `rate_only`     | `rate_only_…`     | `TFF` | High aggregate SYN volume, all handshakes complete, no spoofing.           |
| `ratio_only`    | `ratio_only_…`    | `FTF` | One half-open source; aggregate stays calm but that source's ratio fires.  |
| `pattern_only`  | `pattern_only_…`  | `FFT` | Spoofing rides inside a source that also completes handshakes (ratio calm).|
| `rate_ratio`    | `rate_ratio_…`    | `TTF` | High volume **and** a half-open source.                                    |
| `ratio_pattern` | `ratio_pattern_…` | `FTT` | Half-open source **and** bogon spoofing.                                   |
| `full_attack`   | `full_attack_…`   | `TTT` | High volume, half-open, and spoofed all at once.                           |
| `stealth`       | `stealth_…`       | `FTF` | Low-rate half-open flood — slips under the rate threshold, ratio catches it.|

> `pattern_only` is deliberately constructed so the spoofing source *also* completes handshakes: its own ACKs
> dilute its SYN:ACK ratio below threshold, so `pattern` fires while `ratio` stays calm. A *pure*-spoof source
> would read 100% ratio and trip both — `pattern` and `ratio` are correlated by nature.

---

## The symbol alphabet

`packet_encoding/packet_encoder.py` reduces each attacker packet to one symbol, and marks the end of each
source's per-window substream:

| Symbol | Meaning                                                                 |
| ------ | ---------------------------------------------------------------------- |
| `1`    | Other (SYN-ACK, FIN, RST, …)                                           |
| `2`    | Anomalous SYN — SYN from a reserved/test-net (spoofed) source IP       |
| `3`    | Normal SYN — SYN from an ordinary source IP                            |
| `4`    | ACK (handshake completion)                                             |
| `5`    | End of one `(window, device)` substream                                |

The encoder emits **one line per `(window, device)`** in a fixed device order, padding an idle device with a lone
`5`. The simulator then feeds device *i* to input neuron *i*. "Spoofed" addresses are the RFC 5737 test-net
ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) — non-routable, so lab traffic never escapes.

---

## Generating fresh traffic (Linux)

To regenerate captures instead of using the included ones:

```bash
# 1. Create the victim + 3 attacker namespaces on one bridge (distinct MACs per attacker).
sudo ./traffic_generation/setup_netns.sh 3

# 2. Run every scenario (or name one). Starts the victim server, captures, and fires
#    concurrent per-source attacker streams as defined in scenarios.json.
sudo python3 traffic_generation/scenario_runner.py all
```

Captures (CSV + PCAP) land in `traffic_generation/experiments/`. See
[`traffic_generation/README.md`](traffic_generation/README.md) for the lab topology, the generator/capture CLIs,
and how the scenarios map attacker streams to source devices.

---

## Threshold sweeps (RQ3)

`n_simulator.py` sweeps each feature's threshold across the reference captures in `traffic_generation/experiments/`
and writes `results_<feature>.csv` (accuracy / recall / precision / FPR / F1 per threshold), plus PNG plots if
`matplotlib` is installed. Start the engine, then run it with no arguments:

```bash
uvicorn snp_engine.main:app --port 8000      # in one terminal
python n_simulator.py                        # in another
```

Each capture's expected `(rate, ratio, pattern)` label is read from `scenarios.json` by matching its filename to
its scenario, so there's no labels file to maintain. Override the captures directory or scan ranges if you like:

```bash
python n_simulator.py <captures_dir> --rate-range 20-100 --ratio-range 50-90 --pattern-range 1-10
```

Each feature is scored on its own verdict, independently of the others, so the result is a **perfect-accuracy gap**
per feature — the band of thresholds that separates all scenarios cleanly. On the reference captures these are rate
`[41, 94]`, ratio `[66, 74]`, and pattern `[1, 7]`; the operating points (60, 70, 3) sit inside their gaps. Saved
sweep outputs (CSVs + plots) live in `sweep_results/`.

---

## Notes and assumptions

- **Per-device attribution.** The per-source `Ratio` feature groups by sending **device** (source MAC). In the
  lab, spoofing fakes the IP but not the L2 MAC, so each attacker stays distinguishable. A real victim under
  spoofing generally cannot attribute traffic to a device — this is a methodological assumption of the per-source
  design, appropriate for an SN P / methods study rather than a turnkey defense.
- **Why per-device, not per-IP.** Grouping the ratio per source IP would over-fire: a single spoofed SYN reads
  `S=1, A=0` → 100%. Per-device keeps each device's bogons diluted by that device's own completed handshakes.
- **Windowing.** Captures are split into fixed-Δt windows (default 1 s) with a small grace extension so an
  in-flight handshake's SYN and final ACK stay together; a hard packet cap is a backstop so a half-open flood
  can't hold a window open forever.

---

## License

The code in this repository is released under the **MIT License** (see `LICENSE` at the repository root). Note
that the accompanying paper is published separately and is **not** covered by that license.
