# Feature Documentation: Windowing and Encoding

This document explains, from first principles, how Stages 2 and 3 work: how a raw packet capture
becomes the stream of symbols the detector consumes. The [README](README.md) is the concise
how-to-run; this is the deeper "how and why." It sits between the
[`traffic_generation`](../traffic_generation/FEATURE_DOCUMENTATION.md) stage that produces the
capture and the [`snp_engine`](../snp_engine/FEATURE_DOCUMENTATION.md) stage that runs the
detector — and the symbols defined here are exactly what that engine doc picks up.

There are two steps: `data_preprocessor.py` cuts the capture into time windows, and
`packet_encoder.py` turns each window into symbols.

---

## Part 1 — Why window the capture at all

A capture is one long list of packets; the SN P detector instead reasons about short, finite
**windows** of activity and asks, of each, "does this slice look like a flood?" So the first job
is to cut the capture into windows.

The choice of *how* to cut matters. We use **fixed time windows** of width Δt (one second by
default). The reason is the rate feature: if every window spans the same Δt, then the number of
SYNs in a window is directly proportional to the SYN *velocity*, which is exactly what the rate
detector thresholds on. Cutting by packet count instead would destroy that relationship.

---

## Part 2 — The windowing algorithm

A window closes when its Δt has elapsed — with one refinement and one safety net.

The refinement is **grace**. If the Δt boundary falls in the middle of a handshake — the SYN is in
this window but its completing ACK has not arrived yet — closing immediately would split the
handshake across two windows and distort the ratio. So when the boundary is reached with a
handshake still in flight, the window stays open a little longer (a small `grace` period) to let
it finish.

The safety net is the **hard limit**. A half-open SYN flood never completes its handshakes, so
"wait for the handshake" could otherwise wait forever. A cap on packets-per-window forces the
window closed regardless, guaranteeing progress. `_soft_limit` captures exactly this logic:

```python
def _soft_limit(self, timestamp: float) -> bool:
    if self._window_end is None:
        self._window_end = timestamp + self._max_time_window   # Δt boundary, set from the first packet
    if timestamp < self._window_end:
        return False                                           # still within Δt: keep filling
    # past Δt: close now — unless a handshake is mid-flight, in which case wait up to `grace`
    return len(self._pending_handshakes) <= 0 \
        or timestamp >= self._window_end + self._grace
```

and `add_packet` closes the window when either that fires or the hard cap is hit:

```python
def add_packet(self, row) -> bool:
    if self._soft_limit(float(row["timestamp"])) or len(self._packets) >= self._config.hard_limit:
        return False        # window is full; the caller starts a new one and re-adds this packet
    ...
```

To know whether a handshake is in flight, the preprocessor tracks SYN-ACKs against their ACKs: a
SYN-ACK records a pending handshake, and the matching ACK clears it. While the pending set is
non-empty at a Δt boundary, grace applies.

Each window is written to its own CSV, carrying the eleven columns the encoder needs — including
the **`device`** column (the source MAC) that the encoder will group by.

---

## Part 3 — The symbol alphabet

The encoder reduces each packet to a single symbol, because the detector cares only about a
packet's *role*, not its bytes. Five symbols suffice:

| Symbol | Meaning |
| ------ | ------- |
| `1` | Other — anything that is not a pure SYN or a pure ACK (a SYN-ACK, a FIN, …) |
| `2` | Anomalous SYN — a SYN from a spoofed, reserved-range source address |
| `3` | Normal SYN — a SYN from an ordinary source address |
| `4` | ACK — a completed handshake's acknowledgement |
| `5` | End of one `(window, device)` substream |

The mapping is a short function of the TCP flags and, for a SYN, the source address. A "spoofed"
address is one in the RFC 5737 test-net ranges — the same ranges the generator draws from:

```python
def _is_src_spoof(self, src: str) -> bool:
    return src.startswith(("192.0.2.", "198.51.100.", "203.0.113."))   # RFC 5737 test-nets

def _symbol(self, row) -> str:
    flags = int(row["tcp_flags_raw"])
    if flags == 2:    # a bare SYN
        return ENCODE_ANOMALOUS_SYN if self._is_src_spoof(row["source_ip"]) else ENCODE_NORMAL_SYN
    if flags == 16:   # a pure ACK
        return ENCODE_ACK
    return ENCODE_OTHER
```

The symbol values are not arbitrary: as the [engine doc](../snp_engine/FEATURE_DOCUMENTATION.md)
explains, a symbol injects its numeric value in spikes, and the detector's counter neurons fire on
exactly that count — so symbol `2` activates the anomalous-SYN counter, `3` the normal-SYN counter,
and so on.

---

## Part 4 — One line per (window, device)

The detector treats each source separately, so the encoder does not emit one line per window — it
emits **one line per `(window, device)`**. Two helpers make that work.

First, only *attacker* packets are encoded. Attacker packets are the ones addressed **to** the
server port; the victim's replies leave that port, and including them would make the victim look
like just another source:

```python
def _is_attacker(self, row) -> bool:
    return int(row["destination_port"]) == self._config.target_port
```

Second, the encoder discovers the set of attacker devices once, up front, and sorts them — so that
device *i* always maps to the same input neuron *i* across every window:

```python
def _discover_devices(self) -> list[str]:
    devices = set()
    for window_path in self._window_files():
        with open(window_path) as f:
            for row in csv.DictReader(f):
                if self._is_attacker(row):
                    devices.add(row.get("device", ""))
    return sorted(devices)          # stable order -> device i always maps to input neuron i
```

Encoding then walks each window, groups its attacker packets by device, and writes each device's
symbols followed by the `5` end marker. A device that was idle in a window still gets a line — just
its lone `5` — so the per-device alignment never drifts:

```python
def encode_packets(self) -> None:
    devices = self._discover_devices()
    with open(self._config.file_path, "w+") as out:
        for window_path in self._window_files():
            by_device = collections.defaultdict(list)
            with open(window_path) as f:
                for row in csv.DictReader(f):
                    if self._is_attacker(row):
                        by_device[row.get("device", "")].append(row)
            for device in devices:
                for row in by_device.get(device, []):
                    out.write(self._symbol(row))
                out.write(END_OF_SUBSTREAM + "\n")     # "5" terminates this (window, device)
```

The window files are found by listing the directory and sorting on the window index, rather than
by reconstructing file names — so the encoder works no matter what the directory is called.

---

## Part 5 — End to end

Suppose one window of one device contains two normal SYNs, the ACK that completes one of them, and
one spoofed SYN. The preprocessor has already grouped those packets into the window's CSV and
tagged each with its `device`. The encoder maps them — normal SYN → `3`, ACK → `4`, normal SYN →
`3`, spoofed SYN → `2` — and terminates the substream, producing the line:

```
3432 5
```

(written without the space: `34325`). Stacked across devices and windows, these lines are the
file the [simulator](../simulator.py) feeds to the detector, one `(window, device)` substream per
input neuron. What the detector then does with them is the subject of the
[engine documentation](../snp_engine/FEATURE_DOCUMENTATION.md).
