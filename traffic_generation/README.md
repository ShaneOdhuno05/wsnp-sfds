# Traffic Generation (the multi-source lab)

Stage 1 of the pipeline: generate labeled, **multi-source** SYN-flood traffic and capture it for the detector.

Everything runs on **one Linux host** using network namespaces — there is no second machine, no Windows/Npcap, and
no WiFi-spoofing caveats. A victim and *N* attackers each live in their own namespace on a shared software bridge.

---

## The lab topology

`setup_netns.sh` builds a single software bridge, `br-lab`, in the root namespace (pure L2 forwarding, no IP), and
attaches the victim and every attacker to it. The **victim** is `172.28.5.3` (MAC `02:00:00:00:00:fe`); each
**attacker** *i* runs in its own `attacker<i>` namespace at `172.28.5.(104 + i)` with MAC `02:00:00:00:00:0<i>` — so
`attacker1` is `172.28.5.105`, `attacker2` is `172.28.5.106`, and so on for *N* attackers.

Each attacker namespace has a **distinct, deterministic MAC** (`02:00:00:00:00:0i`). That is the key to
*per-source* detection: a flood can spoof its source **IP**, but not its layer-2 **MAC**, so the victim-side
capture can still attribute every frame to the device that sent it (recorded as the `device` column). All traffic
stays on the local bridge, so spoofed-source packets are delivered reliably and counted exactly once at the
victim's interface. Spoofed IPs come from the RFC 5737 test-net ranges, which are non-routable.

---

## Components

| File                       | Role                                                                                  |
| -------------------------- | ------------------------------------------------------------------------------------- |
| `setup_netns.sh`           | Create the victim + *N* attacker namespaces on the bridge (run once, with `sudo`).    |
| `scenario_runner.py`       | Orchestrate a scenario: start the victim server + capture, fire concurrent streams.   |
| `scenarios.json`           | The 8 labeled scenarios and their per-source streams.                                 |
| `attacker/traffic_generator.py` | Scapy traffic generator: paced SYN floods and/or completed handshakes.           |
| `victim/tcp_server.py`     | Minimal TCP server — keeps port 8080 open so the kernel answers SYNs with SYN-ACKs.   |
| `victim/packet_capture.py` | Sniffs the victim interface; exports a per-packet CSV (incl. `device`) and a PCAP.    |
| `experiments/`             | Output directory; the 8 reference captures live here.                                 |

---

## Quick start

```bash
# 1. Build the lab: victim + 3 attacker namespaces (the argument is N, default 3).
sudo ./setup_netns.sh 3

# 2. Run every scenario (or pass a single scenario name instead of "all").
sudo python3 scenario_runner.py all
```

Captures (`<scenario>_<timestamp>.csv` + `.pcap`) appear in `experiments/`, with a `<scenario>.caplog` capture log.

---

## `setup_netns.sh`

```bash
sudo ./setup_netns.sh [N]      # N attackers, default 3
```

Creates the `br-lab` bridge, the `victim` namespace (`172.28.5.3`, MAC `…:fe`), and `attacker1..N`
(`172.28.5.10{5,6,7,…}`, MACs `…:01,02,03,…`). It disables reverse-path filtering on the victim so spoofed-source
frames aren't dropped before capture, and it is **idempotent** — safe to re-run; it tears down prior namespaces
first and finishes with an attacker→victim connectivity check.

---

## `scenario_runner.py`

```bash
sudo python3 scenario_runner.py <scenario|all> [options]
```

For each scenario it: starts the victim `tcp_server` (unless `--no-server`), launches `packet_capture.py` inside
the victim namespace, waits `--lead-in` seconds for the sniffer to settle, then fires all of the scenario's
streams **concurrently** (one thread per stream), each in its source's attacker namespace. The capture runs for
the scenario duration plus `--margin`.

| Option              | Default      | Description                                                          |
| ------------------- | ------------ | -------------------------------------------------------------------- |
| `--scenarios`       | `scenarios.json` | Path to the scenario definitions.                                |
| `--target-ip`       | `172.28.5.3` | Victim IP (matches `setup_netns.sh`).                                |
| `--attacker-prefix` | `attacker`   | A stream with `"source": i` runs in namespace `<prefix><i>`.         |
| `--victim-ns`       | `victim`     | Victim namespace name.                                               |
| `--interface`       | `veth-vic`   | Interface to capture on (the victim's veth).                         |
| `--margin`          | `8.0`        | Extra capture seconds after the streams finish.                      |
| `--lead-in`         | `5.0`        | Seconds to let the sniffer initialize before firing traffic.         |
| `--no-server`       | off          | Don't manage the victim TCP server (start it yourself).              |

---

## `scenarios.json`

A scenario is a capture duration, a ground-truth `expected` feature list, and a list of attacker **streams**:

```json
"ratio_pattern": {
  "duration": 30,
  "expected": ["syn_ack_ratio", "anomalous_syn_pattern"],
  "streams": [
    { "source": 1, "pps": 8,  "complete_handshake_ratio": 1.0, "duration": 30 },
    { "source": 1, "pps": 15, "complete_handshake_ratio": 0.0, "spoof": true, "duration": 30 },
    { "source": 2, "pps": 8,  "complete_handshake_ratio": 1.0, "duration": 30 },
    { "source": 3, "pps": 8,  "complete_handshake_ratio": 1.0, "duration": 30 }
  ]
}
```

Per-stream fields: `source` (which attacker device, → namespace `attacker<source>`), `pps`, `duration`,
`complete_handshake_ratio` (1.0 = all handshakes complete, 0.0 = pure SYN flood), optional `spoof` and
`sequential_ports`, and optional `start` (delay before the stream begins).

**Multiple streams can share a `source`** — e.g. above, device 1 runs *both* a handshake-completing stream and a
spoofed half-open stream. That overlays bogon SYNs onto a device that also completes handshakes, so its own ACKs
keep its SYN:ACK ratio low: `pattern` can fire without dragging `ratio` along. This is how the scenarios decouple
features that are otherwise correlated.

The eight scenarios (`normal`, `rate_only`, `ratio_only`, `pattern_only`, `rate_ratio`, `ratio_pattern`,
`full_attack`, `stealth`) and their expected `(rate, ratio, pattern)` labels are summarized in the
[top-level README](../README.md#scenarios-and-expected-labels).

---

## The underlying tools

You normally drive these through `scenario_runner.py`, but each runs standalone (`--help` for all flags).

- **`attacker/traffic_generator.py`** — paces TCP traffic at a target `pps` for a duration. SYN-only packets are
  fire-and-forget; completed handshakes are done off the hot path so pacing stays accurate at high rates. The
  runner invokes it with `--target-ip --pps --duration --complete-handshake-ratio --abortive-close` plus
  `--spoof-ips` / `--sequential-ports` as the scenario requires.
- **`victim/tcp_server.py`** — accepts and immediately closes connections on `--port 8080`. Its only job is to
  keep the port open so the kernel returns SYN-ACKs (needed for the SYN:ACK ratio signal).
- **`victim/packet_capture.py`** — Scapy sniffer. Writes a per-packet CSV — including each packet's source MAC as
  the `device` column, the TCP flags (`tcp_flags_raw` + booleans), addresses, ports, and timestamps — plus a PCAP
  for inspection in Wireshark.

---

## Requirements

- A **Linux** host with `sudo` (uses `ip netns`, a bridge, and `veth` pairs).
- **Python ≥ 3.12** and `scapy` (`pip install -r ../requirements.txt`).
