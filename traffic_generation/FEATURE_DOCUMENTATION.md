# Feature Documentation: The Multi-Source Traffic Lab

This document explains, from first principles, how Stage 1 of the pipeline works: how we generate
labeled, multi-source SYN-flood traffic on a single Linux host and capture it for the detector.
The [README](README.md) is the concise how-to-run; this is the deeper "how and why it is built."
Once the traffic is captured, the [`packet_encoding`](../packet_encoding/FEATURE_DOCUMENTATION.md)
stage turns it into symbols and the [`snp_engine`](../snp_engine/FEATURE_DOCUMENTATION.md) stage
runs the detector.

---

## Part 1 — The TCP handshake and the SYN flood

A normal TCP connection opens with a three-way handshake. The client sends a **SYN**; the server
replies **SYN-ACK** and tentatively allocates a half-open connection; the client completes it with
an **ACK**. A **SYN flood** abuses this by sending many SYNs and never sending the final ACK, so
the server's half-open table fills with connections that will never complete.

That attack leaves three observable fingerprints, and they are exactly the three features the
detector watches:

- **Rate** — a flood sends SYNs far faster than ordinary traffic (a *velocity*).
- **Ratio** — a flood's SYNs are never answered with ACKs, so the per-source SYN-to-ACK
  proportion is lopsided.
- **Pattern** — attackers often **spoof** their source IPs, so SYNs arrive from addresses in
  reserved ranges that should never originate real traffic.

The job of this stage is to produce traffic where each of those signals can be turned on or off
independently, so the detector can be tested against every combination.

---

## Part 2 — Why network namespaces

The obvious way to generate this traffic is two machines: an attacker box and a victim box. That
is fragile. Home and office routers quietly drop packets whose source IP is spoofed, so the
pattern feature becomes unreliable; and once an attacker spoofs its IP, the victim has no way to
tell which physical sender a packet came from, which is fatal for *per-source* detection.

We sidestep both problems by running everything on **one Linux host** with **network namespaces**.
A namespace is an isolated network stack — its own interfaces, addresses, and routing. We create
one namespace for the victim and one per attacker, and join them all to a single software
**bridge** (a virtual L2 switch) in the root namespace. Two properties fall out of this:

1. **Spoofing is reliable.** All frames stay on the local bridge, which forwards by MAC and does
   not police source IPs, so a spoofed-source SYN is delivered and counted exactly once.
2. **Every sender is identifiable.** Each attacker namespace is given a fixed, distinct MAC
   address. A flood can forge its IP, but not its layer-2 MAC, so the victim-side capture can
   attribute every frame to the **device** that sent it — which is what lets the ratio feature be
   computed per source.

`setup_netns.sh` builds this. The victim gets `172.28.5.3` and a fixed MAC; then a loop creates
each attacker namespace, wires a `veth` pair from it to the bridge, and assigns the deterministic
MAC `02:00:00:00:00:0i`:

```bash
attacker_mac() { printf '02:00:00:00:00:%02x' "$1"; }

for i in $(seq 1 "$N"); do
  ns="attacker$i"
  ip netns add "$ns"
  ip link add "veth-att$i" type veth peer name "br-att$i"
  ip link set "br-att$i" master "$BRIDGE"          # one end on the shared bridge
  ip link set "veth-att$i" netns "$ns"             # the other inside the attacker namespace
  ip netns exec "$ns" ip link set "veth-att$i" address "$(attacker_mac "$i")"
  ip netns exec "$ns" ip addr add "172.28.5.$((104 + i))/24" dev "veth-att$i"
  ip netns exec "$ns" ip link set "veth-att$i" up
done
```

The script also disables reverse-path filtering on the victim so the kernel does not drop
spoofed-source frames before the capture sees them.

---

## Part 3 — The traffic generator, and why it is non-blocking

`attacker/traffic_generator.py` produces the traffic for one attacker. Its hard requirement is to
hit a target **packets-per-second** rate accurately, because the rate feature depends on it.

The tempting Scapy approach is to complete each handshake with `sr1()` — send a packet and block
until the reply arrives. That quietly destroys the rate: if every connection waits for a SYN-ACK
round-trip, the real throughput is governed by handshake latency, not by `pps`. (This was a real
bug in an earlier version; the effective ceiling sat around 25 pps regardless of the requested
rate.)

The fix is to keep the generator's loop **non-blocking** and push anything that would block onto a
thread pool. Setup creates one reusable raw socket for sending SYNs and a pool for completing
handshakes:

```python
def _setup(self):
    self._l3 = conf.L3socket()                       # one reused socket -> avoids the ~25 pps ceiling
    self._pool = ThreadPoolExecutor(max_workers=64)  # completed handshakes run here, off the hot path
```

The main loop paces itself with a monotonic clock and, on each tick, either fires a bare SYN or
hands a full handshake to the pool — but never waits:

```python
interval = 1.0 / self.config.pps
next_send = time.perf_counter()
while not self._stop_requested:
    now = time.perf_counter()
    if self.config.duration > 0 and (now - start) >= self.config.duration:
        break
    if now < next_send:
        time.sleep(next_send - now)          # precise sleep until the next slot
        continue
    complete = random.random() < self.config.complete_handshake_ratio
    if complete and not self.config.spoof_ips:
        self._pool.submit(self._complete_handshake_os)   # real handshake, OFF the hot path
    else:
        self._emit_syn(src_ip, src_port)                 # flood SYN (or a spoofed "normal")
    next_send += interval
```

A flood SYN is just a crafted packet pushed through the reused socket — fire-and-forget, no reply
awaited:

```python
def _emit_syn(self, src_ip, src_port):
    seq = random.randint(1000000, 4294967295)
    pkt = IP(src=src_ip, dst=self.config.target_ip) / TCP(
        sport=src_port, dport=self.config.target_port, flags="S", seq=seq
    )
    self._l3.send(pkt)
```

A *completed* handshake is handed to the kernel rather than hand-rolled in Scapy: a normal
`socket.connect()` performs the whole SYN / SYN-ACK / ACK exchange correctly, and because the
kernel itself opened the connection there is no stray-RST problem to suppress. The interesting
detail is the close. By default TCP closes with a FIN exchange, which adds ACKs to the capture and
muddies the SYN-to-ACK ratio. Setting `SO_LINGER` to zero makes the close an abrupt **RST**
instead, so a completed connection contributes its one handshake ACK and nothing more:

```python
def _complete_handshake_os(self):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(self.config.handshake_timeout)
    try:
        s.connect((self.config.target_ip, self.config.target_port))  # kernel does SYN/SYN-ACK/ACK
        if self.config.abortive_close:
            # RST on close() -> no FIN teardown ACKs, so the SYN:ACK ratio stays sensitive
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    finally:
        s.close()
```

Spoofing and port choice are small helpers: `_get_source_ip` returns the real IP, or a random
address from the RFC 5737 test-net ranges when `--spoof-ips` is set; `_get_source_port` returns a
random ephemeral port, or sequential ports when `--sequential-ports` is set.

---

## Part 4 — The victim: a server to answer, a sniffer to record

Two small programs run in the victim namespace.

`victim/tcp_server.py` exists only so the kernel will answer SYNs with SYN-ACKs — without a
listener, the kernel would reply RST ("connection refused") and there would be no handshakes to
complete. It accepts each connection on its own thread and closes it immediately:

```python
while self._running:
    try:
        client_socket, client_addr = self._server_socket.accept()
        threading.Thread(target=self._handle_connection,
                         args=(client_socket, client_addr), daemon=True).start()
    except socket.timeout:
        continue
```

`victim/packet_capture.py` sniffs the victim's `veth` interface and writes a per-packet CSV. The
field that makes per-source detection possible is `device` — the **source MAC**, which is stable
per attacker and unaffected by IP spoofing. It also pre-computes the flag booleans the
preprocessor needs:

```python
if packet.haslayer(Ether):
    result["device"] = packet[Ether].src          # sending device, stable under IP spoofing

syn = bool(tcp.flags.S); ack = bool(tcp.flags.A)
fin = bool(tcp.flags.F); rst = bool(tcp.flags.R)
result["is_syn"]     = syn and not ack             # a bare SYN
result["is_syn_ack"] = syn and ack                 # the server's reply
result["is_ack"]     = ack and not syn and not fin and not rst  # a handshake-completing ACK
```

It saves both a PCAP (for opening in Wireshark) and the CSV the next stage consumes.

---

## Part 5 — Orchestrating a scenario

`scenario_runner.py` ties the pieces together for a whole experiment. For each scenario it starts
the victim server, opens a capture in the victim namespace, waits a moment for the sniffer to
settle, then fires the scenario's attacker **streams concurrently** — one thread each, each inside
its own attacker namespace.

A scenario is defined in `scenarios.json` as a capture duration, a ground-truth `expected` label,
and a list of streams:

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

Each stream's `source` selects which attacker namespace it runs in, and its other fields become
generator flags:

```python
def stream_cmd(s, target_ip, attacker_ns):
    cmd = in_ns(attacker_ns, GEN, "--target-ip", target_ip,
                "--pps", str(s["pps"]), "--duration", str(s["duration"]),
                "--complete-handshake-ratio", str(s.get("complete_handshake_ratio", 1.0)),
                "--abortive-close")
    if s.get("spoof"):            cmd.append("--spoof-ips")
    if s.get("sequential_ports"): cmd.append("--sequential-ports")
    return cmd

def fire_stream(idx, s, target_ip, attacker_prefix):
    ns = f"{attacker_prefix}{s.get('source', 1)}"   # stream -> its device's namespace
    subprocess.run(stream_cmd(s, target_ip, ns), ...)
```

Notice in the example above that **two streams share `source: 1`**: one completes its handshakes,
the other is a spoofed half-open flood. Running both on the *same* device is deliberate — that
device's own ACKs dilute its SYN-to-ACK ratio below threshold, so the scenario can exercise the
`pattern` feature without also tripping `ratio`. This is how the scenarios decouple features that
would otherwise move together.

---

## Part 6 — Running it end to end

Putting the whole stage together is two commands:

```bash
sudo ./setup_netns.sh 3                 # build the victim + 3 attacker namespaces
sudo python3 scenario_runner.py all     # run every scenario, capturing each
```

Each scenario leaves a `<name>_<timestamp>.csv` (and matching `.pcap`) in `experiments/`, carrying
the `device` column and the flag booleans. From there the [`packet_encoding`
stage](../packet_encoding/FEATURE_DOCUMENTATION.md) windows and encodes it, and the detector takes
over.
