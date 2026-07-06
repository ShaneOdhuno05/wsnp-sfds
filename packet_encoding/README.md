# Packet Encoding (windowing + symbol encoding)

Stage 2–3 of the pipeline. Turns a raw capture into the symbol sequences the SN P detector consumes:

1. **`data_preprocessor.py`** — splits a capture into fixed-Δt **windows**.
2. **`packet_encoder.py`** — encodes each window's packets into the SN P symbol alphabet, **one line per
   `(window, device)`**.

> In normal use you don't run these directly — [`simulator.py`](../simulator.py) calls both internally when given
> `--file-path`. They're documented here because they're also runnable standalone and define the data contract the
> detector depends on.

---

## Stage 2 — `data_preprocessor.py`

Reads a capture **CSV** (the columns produced by the lab's packet capture) or a **PCAP**, and writes one CSV per
window into a directory named after the input file.

```bash
python packet_encoding/data_preprocessor.py <capture.csv> [options]
```

| Flag                | Default | Description                                                                      |
| ------------------- | ------- | -------------------------------------------------------------------------------- |
| `--export-dir-path` | (auto)  | Where to write windowed CSVs. Defaults to a dir named after the input file.      |
| `--max-time-window` | `1.0`   | **Δt** — fixed window width in seconds. This is what closes a window.            |
| `--grace`           | `0.05`  | Max seconds to extend past Δt so an in-flight handshake's ACK joins its SYN.      |
| `--hard-limit`      | `400`   | Backstop: force a window break at this many packets (so a half-open flood can't hold a window open). |
| `--target-size`     | `15`    | Vestigial — retained for compatibility; no longer gates the window close.        |

**Windowing.** A window closes when Δt has elapsed. If handshakes are still in flight at the boundary, it waits up
to `grace` seconds for them to complete, then closes regardless — so a SYN flood (whose SYN-ACKs are never ACKed)
cannot stall windowing. Fixed-Δt windows make the per-window SYN count proportional to *velocity*, which is what
the rate feature measures.

**Output.** Each window is written as `windowed_packets-<capture-name>_<id>.csv` with 11 columns:
`packet_no, timestamp, device, source_ip, destination_ip, protocol, source_port, destination_port,
tcp_flags_raw, seq_num, ack_num`. The **`device`** column (the sending host's source MAC) is what makes
per-source detection possible downstream.

---

## Stage 3 — `packet_encoder.py`

Reads the windowed CSVs and writes a single encoded text file.

```bash
python packet_encoding/packet_encoder.py <windowed_dir>
```

It expects the `windowed_packets-*.csv` files produced by Stage 2 inside `<windowed_dir>`, and writes
`encoded-<windowed_dir>.txt` there.

### Symbol alphabet

Each attacker packet maps to one symbol; every `(window, device)` substream ends with a `5`:

| Symbol | Meaning                                                            | Rule                                          |
| ------ | ----------------------------------------------------------------- | --------------------------------------------- |
| `1`    | Other (SYN-ACK, FIN, RST, …)                                      | anything not matched below                    |
| `2`    | Anomalous SYN — from a reserved/test-net (spoofed) source IP      | `tcp_flags_raw == 2` and source IP in RFC 5737 |
| `3`    | Normal SYN — from an ordinary source IP                           | `tcp_flags_raw == 2` and source IP not RFC 5737 |
| `4`    | ACK (handshake completion)                                        | `tcp_flags_raw == 16`                         |
| `5`    | End of one `(window, device)` substream                           | emitted after each device's packets in a window |

### Per-device emission

For each window, the encoder writes **one line per device**, in a fixed device order discovered across the whole
capture (sorted source MACs, so device *i* always maps to input neuron *i*). A device that is idle in a window
contributes just its `5`. Only **attacker** packets are encoded — packets addressed *to* the server port are
attacker-originated; the victim's replies (sent *from* the server port) are excluded so the victim never becomes a
spurious "device".

> Because of this, the simulator's `--input-sources` must equal the number of attacker devices in the capture.

"Spoofed" ranges are the RFC 5737 test-net blocks `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` — the same
ranges the traffic generator uses, and non-routable so lab traffic never escapes.

---

## Standalone end-to-end example

```bash
# From the repository root. Window a capture into ./my_run/ ...
python packet_encoding/data_preprocessor.py \
    traffic_generation/experiments/full_attack_2026-06-26_150822.csv \
    --export-dir-path my_run

# ... then encode it (writes my_run/encoded-my_run.txt).
python packet_encoding/packet_encoder.py my_run
```
